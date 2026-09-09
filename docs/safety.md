# Safety and data handling

[Back to the main README](../README.md)

Generate keys with `turbocrypt keygen` and keep a backup away from the data it
protects.

Password protection limits access to a key file at rest. Changing that
password does not change the encryption key.

`keygen`, `change-password` and the configuration commands write a new file
and rename it into place.

If the destination is a symbolic link, the link is replaced by a regular file
rather than followed.

Keep the plaintext until a full `verify` succeeds on the encrypted copy.
`--dry-run` is useful before a large directory job, particularly when exclude
patterns are involved.

More threads are not always faster.

A small worker count often suits trees of small files, while a larger buffer
can help with very large files.

Measure on the storage you actually use; `turbocrypt bench` is available for
that.

The [Git integration guide](git.md#metadata-and-limitations) describes the
metadata exposed by private files stored in a public repository.
