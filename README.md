# SOC Home Lab: SIEM Alert Investigation with AI-Assisted Triage

I built this lab to get actual hands-on SOC experience before applying for analyst roles, instead of just putting "familiar with SIEM tools" on a resume and hoping nobody asks a follow-up question. It's a small, self-contained Security Operations Center running on three VMs: a Wazuh SIEM, a Windows endpoint I deliberately attacked using Atomic Red Team, and a Python pipeline that pulls real alerts and uses an LLM to draft triage summaries for me to review.

I didn't follow a tutorial and take screenshots along the way. Almost everything below broke at least once before it worked, and I've written up the breaking just as much as the building, because that's closer to what the job actually looks like day to day.

![Lab architecture](diagrams/architecture_diagram.png)

## What's actually in this lab

- **Kali Linux**: attacker VM, used for brute-force testing (Hydra) and for hosting Atomic Red Team's test tooling.
- **Windows 10 VM**: the victim endpoint. Instrumented with Sysmon (SwiftOnSecurity config) and enrolled as a Wazuh agent.
- **Wazuh Manager + Indexer**: single-node SIEM, OVA deployment, running the default MITRE ATT&CK-mapped detection rules.
- **A Python triage script**: pulls recent alerts straight from the Wazuh Indexer's API, enriches file hashes and IPs through VirusTotal and AbuseIPDB, then asks Google's Gemini to draft a plain-English summary of what each alert means. I review every draft myself and either agree with it, correct it, or override it entirely.

All three VMs sit on an isolated internal network with no route to the internet by default. That turned out to matter more than I expected, more on that further down.

## What I actually tested

I ran 11 separate techniques through Atomic Red Team, spanning six MITRE ATT&CK tactics: Credential Access, Discovery, Defense Evasion, Execution, Persistence, and Privilege Escalation. I wanted breadth here instead of just repeating the same PowerShell technique five times in a row, since a real environment doesn't attack you one way.

<table border="1" cellpadding="8" cellspacing="0">
<thead>
<tr>
<th>Technique</th>
<th>Tactic</th>
<th>What Wazuh Caught</th>
<th>Confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td>T1003.002 – Credential Dumping (SAM hive)</td>
<td>Credential Access</td>
<td>PowerShell copying the SAM hive from VSS, and reg.exe dumping it directly. Two separate rules fired, both high severity.</td>
<td>High</td>
</tr>
<tr>
<td>T1016 – Network Config Discovery</td>
<td>Discovery</td>
<td>Generic "system information discovery" rule, moderate severity.</td>
<td>Moderate</td>
</tr>
<tr>
<td>T1036.003 – Masquerading</td>
<td>Defense Evasion</td>
<td>Sysmon flagged processes renamed to look like <code>lsm.exe</code>, <code>svchost.exe</code>, and <code>lsass</code>. Caught by its own naming heuristics.</td>
<td>High</td>
</tr>
<tr>
<td>T1047 – Windows Management Instrumentation</td>
<td>Execution</td>
<td>Nothing specific fired. Only generic low-severity noise.</td>
<td><strong>Gap: no rule exists for this</strong></td>
</tr>
<tr>
<td>T1053.005 – Scheduled Task</td>
<td>Execution / Persistence / PrivEsc</td>
<td>Strong supporting signals (base64 in registry, script dropped in AppData) but no dedicated "task created" rule.</td>
<td>Partial</td>
</tr>
<tr>
<td>T1059.001 – PowerShell</td>
<td>Execution</td>
<td>Caught a base64-encoded command spawning another PowerShell process. Exactly the obfuscation pattern this rule exists for.</td>
<td>High</td>
</tr>
<tr>
<td>T1059.003 – Command Shell</td>
<td>Execution</td>
<td>Only generic chaining alerts. Nothing that stood out from routine admin scripting.</td>
<td>Low / generic only</td>
</tr>
<tr>
<td>T1136.001 – Create Local Account</td>
<td>Persistence</td>
<td><code>net1.exe</code> user-creation command, caught directly.</td>
<td>High</td>
</tr>
<tr>
<td>T1543.003 – Create/Modify Windows Service</td>
<td>Persistence / PrivEsc</td>
<td>New service creation plus registry evidence. Multiple corroborating signals.</td>
<td>High</td>
</tr>
<tr>
<td>T1547.001 – Startup Folder Persistence</td>
<td>Persistence / PrivEsc</td>
<td>PowerShell copying an executable into the Windows startup folder. Very specific, high severity.</td>
<td>High</td>
</tr>
<tr>
<td>T1548.002 – UAC Bypass (FodHelper)</td>
<td>PrivEsc / Defense Evasion</td>
<td>Five separate rules correlated into one story: the FodHelper invocation, the specific registry key it uses, and the auto-elevation behavior itself.</td>
<td><strong>Very high, genuinely the best result in the lab</strong></td>
</tr>
</tbody>
</table>

<br>

9 out of 11 produced a real, specific detection. 1 was a clean miss (no WMI-specific rule exists in Wazuh's default ruleset), and 1 only had partial supporting evidence. I'd rather show that honestly than pretend everything was a perfect catch. Knowing how to tell a real detection from a weak one is a more useful skill to demonstrate than a perfect scorecard.

## The false positive I wasn't expecting to find

One thing stood out across all 11 test runs. A single Wazuh rule (92213, "executable dropped in a folder commonly used by malware," severity 15, the highest in the ruleset) fired as the **top alert in every single run**, no matter what technique I was actually testing.

I dug into it instead of just ignoring it. Turns out Atomic Red Team's PowerShell-based test runner creates a small housekeeping file (`__PSScriptPolicyTest_*.ps1`) in the Temp folder every time it runs anything. Completely harmless, just PowerShell checking its own script execution policy. But the rule is written to flag any file landing in that folder as malware-like, based purely on the path, with no regard for what the file actually is.

So technically Wazuh "detected" something in all 11 runs, but the loudest, highest-severity alert each time was actually noise. In a real SOC, a rule like this trains analysts to tune it out, which is exactly how real attacks end up hiding in plain sight. If I were running this ruleset for real, I'd either add an exception for PowerShell's own known policy-test file pattern, or rewrite the rule to check file content or hash instead of just the folder path.

## The AI-assisted triage layer

SOC teams are increasingly leaning on LLMs to help with alert volume, so I built a small pipeline to actually try it rather than just read about it:

1. Pull the most recent alerts directly from Wazuh's Indexer API.
2. For any alert containing a file hash or IP, check it against VirusTotal and AbuseIPDB.
3. Hand the enriched alert to Gemini and ask for a plain-English summary, a suggested triage category, and a likely MITRE mapping.
4. Review every single draft myself and either agree, disagree, or add context before accepting it.

What genuinely surprised me: the AI's drafts were reasonable almost every time. It correctly called two DNS timeout alerts benign, and correctly flagged ambiguous registry deletions as needing escalation. But I also caught it giving **inconsistent labels on functionally identical alerts**, the same rule, same host, seconds apart, labeled "likely false positive" once and "needs escalation" the next time. That's not a small detail to brush past. It's the exact reason an AI draft can't be the final word, and I'd rather document it than bury it. "The AI helped" is a less useful story than "the AI helped, and here's specifically where I had to catch it out."

## Problems I ran into (and actually had to solve)

I'm including this section because I think it's more useful to a recruiter than a list of green checkmarks. Anyone can follow a tutorial start to finish. These are the parts where something broke and I had to actually work out why.

**The Wazuh VM just sat on the splash screen.**
Powered it on, got the Wazuh logo, and nothing happened for way longer than it should have. Turned out the OVA had imported with an extremely old virtual hardware compatibility level (6.5-7.x) that didn't get along with my much newer VMware Workstation build. Removing a leftover floppy drive and upgrading the VM's hardware version fixed it. First I'd actually suspected a UEFI/BIOS firmware mismatch, which turned out to be a dead end. Lesson: when something hangs with zero error message, check what you're actually running before chasing the obvious theory.

**Alerts just weren't showing up. For hours.**
This was the most frustrating one. The agent was connected, the manager's services were all healthy, I'd rechecked the Sysmon config a dozen times, and still nothing in the dashboard. Turned out VMware Tools' time-sync setting was off on the Wazuh VM, so after a few power cycles its clock had drifted out of sync with the Windows VM. Every alert was technically arriving, just stamped with a timestamp the dashboard's "last 10 minutes" filter didn't think was recent. Nothing in any log said the clock was wrong. I only caught it because the agent's "last keep-alive" timestamp looked like it was sitting in the future. Now I check VM clock sync first, not last, whenever something seems to vanish without a trace.

**The indexer flatly refused connections from outside the VM.**
My script could talk to Wazuh from inside the manager VM itself but not from my own laptop. Running `ss -tlnp` showed the indexer was only bound to `127.0.0.1`. It was never going to accept outside connections no matter what firewall rules I opened. Had to edit OpenSearch's config directly (`network.host: 0.0.0.0`) and restart the service.

**A free-tier AI API is not the same thing as a stable one.**
Once I ran out of budget for paid Claude API credits, I switched to Google's free-tier Gemini. It works, but getting there took its own round of debugging: wrong auth method (it wanted a header, not a query parameter), a model name that returned a flat 404, and then once that was sorted, actual server overload (503s) and timeouts under completely normal use. I ended up writing retry logic with increasing backoff instead of assuming my own code was broken every time a request failed. Good reminder that "free" and "production-stable" aren't the same thing.

**Windows Home edition quietly doesn't have half the tools SOC guides assume you have.**
`secpol.msc`, used to configure audit policies for login and logoff events, simply doesn't exist on Windows Home. Rather than rebuild the whole VM, I found the command-line equivalent (`auditpol`) does exactly the same job and works on every edition.

**Some Atomic Red Team tests need external tools that aren't included by default.**
A couple of tests reference tools like BloodHound and SharpHound, which aren't bundled in for licensing and size reasons, and the error message doesn't make that obvious. Lesson: when a test fails with a missing-module error, check whether it depends on an external payload before assuming the environment itself is broken.

## What I'd do differently with more time

- Add detection coverage for WMI execution (T1047) specifically, since the default ruleset has a real gap there.
- Fix the AppData/Temp folder false-positive rule instead of just documenting it.
- Feed the AI triage layer richer raw event data. Right now it's missing Wazuh's `syscheck`-specific fields for file-integrity alerts, which capped how useful its drafts could be for those.
- Extend the lab into basic cloud logging (forwarding AWS CloudTrail into the same Wazuh instance) to practice a hybrid on-prem and cloud detection setup.

## Why this project, specifically

Everything in this write-up is something I can talk through in detail, including the parts that went wrong, because I was the one who had to work out why they went wrong in the first place.

---

**Stack:** VMware Workstation, Wazuh 4.14, Sysmon, Atomic Red Team, Python, VirusTotal API, AbuseIPDB API, Google Gemini API

**Contact:** Prasanna Venkatesh S | [linkedin.com/in/undestined](https://linkedin.com/in/undestined) | [tryhackme.com/p/undestined](https://tryhackme.com/p/undestined)
