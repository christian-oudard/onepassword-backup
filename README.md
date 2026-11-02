# onepassword-backup

Export a 1Password account to a 1PUX file from the command line.

The 1Password CLI, `op`, has no export command, and the desktop app is the only official way to get a 1PUX file. `onepassword-backup` reads every item through `op` and writes the same format, which 1Password and other password managers can import.

## Usage

Run it from a clone, which needs Python 3.11 or later, or through Nix with `nix run github:christian-oudard/onepassword-backup`. Either way it needs a signed-in `op` session:

```
$ eval "$(op signin)"
$ ./onepassword-backup
```

With no argument, it writes `1PasswordExport-<account ID>-<date>-<time>.1pux` in the current folder, the name the desktop app gives its exports. To choose the name, pass it as an argument, ending in `.1pux`:

```
$ ./onepassword-backup backup.1pux
```

It refuses to overwrite an existing file and writes it with mode 0600. On a terminal it shows how many items and files it has read so far. At the end it prints a count of items per category and the number of files.

The output is unencrypted. Write it only into encrypted storage, such as a mounted VeraCrypt container.

## Restoring

Import the file with a 1Password 8 app. The import adds every item as a new copy, even if the vault already holds it, so import into an empty vault.

## What it exports

- Every item in every vault, archived ones included
- All categories, with all fields, empty ones included, and notes, URLs, tags and favorite state
- Document files and file attachments, stored in the archive's `files/` folder

An item category or field type it doesn't know stops the export with an error, so nothing is dropped silently.

Passkeys, password history and "Sign in with" records are not exported, since `op` can't read them. The desktop app's export doesn't include passkeys either.

## Tests

```
$ python3 -m unittest
```
