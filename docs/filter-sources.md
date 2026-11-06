# Source selection and refresh behavior

Source controls should distinguish **Ignore**, **Block** and **Allow**. Ignore
contributes no rule. Allow creates exceptions and must not be used as a synonym
for disabling a list. Enforced categories retain precedence over normal allows.

Compile enabled sources into one exact index. Disabling a source removes only its
contributions; domains and categories supplied by other enabled sources remain.
Keep small catalog/settings records for disabled sources. Under a strict storage
budget, discard their payloads and fetch them again when enabled. Downloading,
compiling and activating a replacement must fit the update budget.

Coverage belongs in the source details. [StevenBlack](https://github.com/StevenBlack/hosts#list-of-all-hosts-file-variants)
publishes both category-only and base-plus-category variants. Allowing a combined
feed may exempt domains outside the category implied by a short display label.
[OISD](https://oisd.nl/) separates its general protection and NSFW lists; its Big
list is not an adult/gambling policy. Aggregated sources overlap, so their counts
cannot simply be added to estimate unique coverage.

The planned UI should show the full URL, coverage, format, successful refresh time,
revision/hash, overlap, storage cost and update errors. Preview the effect of mode
changes, including blocks restored by removing an allow source. Manual refresh
and jittered scheduling should work on headless servers; battery/network deferral
is a separate desktop preference.

The offline source-selection compiler and on-demand development downloader are
implemented. The UI, background scheduler and live activation are not.
