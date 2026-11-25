# Operator experience review

Reviewed the embedded panel at `73fdff9`, the two quick starts, the management CLI guide and the MCP guide. The walkthrough follows an operator from installation through recovery. Findings below come from screen markup and action handlers. The OAuth check used a local HTTPS server and disposable PostgreSQL database. Mobile layout, screen-reader output and a live OpenClaw installation still need hands-on verification.

## Address first

| Priority | Operator task and finding | Acceptance check for the change |
| --- | --- | --- |
| High | Confirm a privileged change. In `promptStepUp`, a server error is labelled “Incorrect password” and the password dialog opens again. A delayed confirmation also writes the returned token without checking that the initiating session is still active. This affects actions across the panel. | Give a service error a recovery action. Only an incorrect password should invite a password retry. End the session while confirmation is pending and verify the original action cannot resume in the next session. |
| High | Publish the first service. Both quick starts sent the operator to an “Add” control and instructed them to apply manually after every save. This review updates both guides to follow inline certificate issuance, review, save and the pending-change branch. | Follow either guide with a fresh hostname. Locate every named control, select a ready certificate, and check the apply outcome before opening the hostname. |
| Medium | Inspect an SSH ban after connectivity drops. `loadFail2banOverview` sets the jail list to loading before fetching. A rejected fetch has no local recovery handler and the previous jail selector can survive a failed refresh. | Disconnect during refresh. Show that the jail list is unavailable, disable actions that depend on it, and restore them after a successful refresh. Announce the outcome to assistive technology. |
| Medium | Recover an ACME or security settings form after the saved settings fail to load. Several forms instruct the operator to navigate to **Settings → Load from server**, then return to the original screen. | Offer a retry beside the affected form. Preserve edits and distinguish a failed read from an empty saved value. |
| Medium | Investigate one publication after testing a Count rule. **Events & audit** offers a period selector for publication rule matches, but no hostname selector. Multiple hosts share one table. | From one publication, inspect its matches for the selected period and clear the host filter to return to all publications. |
| Lower | Restore from backup during an outage. **System → Backup and restore** gives the command and the impact, then names a repository path as plain text. | Provide a usable recovery-guide link alongside the command and a way to locate the same instructions when the appliance is offline. |

## Coverage and remaining walkthroughs

The privileged confirmation finding has been addressed. A session change cancels the password prompt and invalidates pending confirmations and retries. The panel distinguishes an incorrect password from throttling and service errors. The regression scenarios are in `TestPrivilegedConfirmationLifecycle`.

- **Install, sign in, recover.** The quick start identifies the management URL and the console enrollment command. The CLI guide covers access reset and appliance reset separately. Verify on a clean VM that an operator can recover panel access without choosing an appliance reset.
- **Dashboard, Applications, Certificates and Edge changes.** Preserve the distinction between saved configuration, acknowledged apply and live traffic. Test one unsuccessful issuance and one pending change through to recovery on a narrow screen.
- **Security, CrowdSec, Fail2Ban and Events & audit.** Test the same refusal from the publication and investigation screens. The operator should be able to identify the enforcing component before changing a policy or lifting a ban.
- **System, Network, Users and Settings.** Network changes already offer review and timed confirmation. Exercise keyboard-only reconnect and confirmation, and check that an expired session clears sensitive fields. In Users, verify that the operator can distinguish panel access from a local system account.
- **MCP and About.** Operate → MCP exposes the HTTPS URL, read-only consent, approved connections and revocation. About identifies the running version and component version sources for support. The HTTPS integration test exercised `doctor` with no grant (401), with approval (200), and after revocation (401). A refresh attempt after revocation was rejected. A real Gateway pairing remains a separate interoperability check.
