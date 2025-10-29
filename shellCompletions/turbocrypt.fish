# ~/.config/fish/completions/turbocrypt.fish
# turbocrypt completions (top-level descriptions, --help, allow files for config add/remove-exclude)

set -l cmds 'keygen' 'change-password' 'encrypt' 'decrypt' 'verify' 'config' 'bench'

# Offer top-level commands only when none present; do not show files at this point.
# Provide per-command descriptions (so the UI shows what each command does).
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' --no-files -a keygen -d "Generate a new key"
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' --no-files -a change-password -d "Add/change/remove password on a key file"
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' --no-files -a encrypt -d "Encrypt files or directories"
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' --no-files -a decrypt -d "Decrypt files or directories"
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' --no-files -a verify -d "Verify encrypted data integrity"
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' --no-files -a config -d "View or change configuration"
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' --no-files -a bench -d "Run performance benchmarks"

# Top-level help flags (available before a subcommand)
complete -c turbocrypt -n 'not __fish_seen_subcommand_from keygen; and not __fish_seen_subcommand_from change-password; and not __fish_seen_subcommand_from encrypt; and not __fish_seen_subcommand_from decrypt; and not __fish_seen_subcommand_from verify; and not __fish_seen_subcommand_from config; and not __fish_seen_subcommand_from bench' -l help -s h -d "Show help"

# ------------------------
# keygen
# ------------------------
complete -c turbocrypt -n '__fish_seen_subcommand_from keygen' -l password -d "Generate a password-protected key"
complete -c turbocrypt -n '__fish_seen_subcommand_from keygen' -a '(__fish_complete_path)' -d "Output key file"

# ------------------------
# change-password
# ------------------------
complete -c turbocrypt -n '__fish_seen_subcommand_from change-password' -l remove-password -d "Remove password protection from key"
complete -c turbocrypt -n '__fish_seen_subcommand_from change-password' -a '(__fish_complete_path)' -d "Key file to modify"

# ------------------------
# encrypt / decrypt / verify common options
# ------------------------
for cmd in encrypt decrypt verify
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l key -r -a '(__fish_complete_path)' -d "Path to key file"
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l password -d "Use password-protected key (prompt)"
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l in-place -d "Operate in place (overwrite source)"
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l encrypted-filenames -d "Encrypt/decrypt filenames"
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l enc-suffix -d "Automatically add/remove .enc suffix"
    # exclude/context are patterns (no file completion)
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l exclude --no-files -r -d "Exclude pattern (glob)"
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l context --no-files -r -d "Context string"
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l threads -r -a "1 2 4 8 16 32" -d "Worker threads"
    complete -c turbocrypt -n "__fish_seen_subcommand_from $cmd" -l dry-run -d "Preview without performing operation"
end

# quick verification flag (verify only)
complete -c turbocrypt -n '__fish_seen_subcommand_from verify' -l quick -d "Quick verification (check only key correctness)"

# ------------------------
# config subcommands (with helpful descriptions)
# ------------------------
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a show -d "Show current configuration"
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a set-key -d "Set default key path"
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a set-threads -d "Set default thread count"
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a set-buffer-size -d "Set IO buffer size (bytes)"
# add/remove-exclude in config takes file arguments -> allow path completion
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a add-exclude -d "Add an exclude pattern or file"
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a remove-exclude -d "Remove an exclude pattern or file"
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a set-ignore-symlinks -d "Set symlink behavior (true/false)"
complete -c turbocrypt -n '__fish_seen_subcommand_from config' -f -a set-encrypted-filenames -d "Set default encrypted-filenames behavior (true/false)"

# config args: allow path completion for set-key and add/remove-exclude
complete -c turbocrypt -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from set-key' -a '(__fish_complete_path)' -d "Path to key"
# add-exclude/remove-exclude in config: allow files or patterns (offer files)
complete -c turbocrypt -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from add-exclude' -a '(__fish_complete_path)' -d "File or pattern to add to exclude list"
complete -c turbocrypt -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from remove-exclude' -a '(__fish_complete_path)' -d "File or pattern to remove from exclude list"
complete -c turbocrypt -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from set-threads' -a "1 2 4 8 16 32" -d "Threads"
complete -c turbocrypt -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from set-buffer-size' -a "4096 65536 1048576 8388608" -d "Buffer size (bytes)"
complete -c turbocrypt -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from set-ignore-symlinks' -a "true false" -d "Ignore symlinks (true/false)"
complete -c turbocrypt -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from set-encrypted-filenames' -a "true false" -d "Default filename encryption (true/false)"

# ------------------------
# positional/file completions: only after encrypt/decrypt/verify
# ------------------------
complete -c turbocrypt -n '__fish_seen_subcommand_from encrypt; or __fish_seen_subcommand_from decrypt; or __fish_seen_subcommand_from verify' -a '(__fish_complete_path)' -d "File or directory"

