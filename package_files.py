#!/usr/bin/env python3
import os
import zipfile
import subprocess
import shutil



import os
import re
import shlex

def normalize_path(p: str) -> str:
    """
    Normalize a user-supplied path (macOS-friendly):
    - Strip surrounding whitespace and quotes
    - If the path looks shell-escaped (drag-and-drop), unescape backslashes
      e.g. '\\ ' -> ' ', '\\(' -> '(', '\\#' -> '#'
    - Expand ~ and make absolute
    """
    if not p:
        return p

    p = p.strip()

    # If the user pasted something quoted, remove only outer quotes
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1]

    # First try as-is (covers normal pasted paths with spaces)
    candidate = os.path.abspath(os.path.expanduser(p))
    if os.path.exists(candidate):
        return candidate

    # If it looks like a shell-escaped path, unescape backslashes.
    # macOS drag-drop tends to escape special chars with backslashes.
    unescaped = re.sub(r'\\(.)', r'\1', p)

    # Also handle cases where the user pasted a shell-style token/quoted path
    # (shlex will interpret backslash escapes + quotes).
    try:
        parts = shlex.split(p)
        if len(parts) == 1:
            shlex_one = parts[0]
        else:
            shlex_one = None
    except ValueError:
        shlex_one = None

    # Prefer whichever resolves to an existing path
    for q in [unescaped, shlex_one]:
        if not q:
            continue
        candidate = os.path.abspath(os.path.expanduser(q))
        if os.path.exists(candidate):
            return candidate

    # Fall back to the best-effort unescaped absolute path
    return os.path.abspath(os.path.expanduser(unescaped))


def zip_directory_into_objects(package_dir: str, objects_dir: str, zip_basename: str) -> str:
    """
    Create a ZIP of the package_dir (excluding the objects/ folder) inside objects_dir.
    The arc names will include the top-level package directory name.
    """
    package_dir = os.path.normpath(package_dir)
    parent_of_package = os.path.dirname(package_dir)

    if zip_basename.lower().endswith(".zip"):
        zip_basename = zip_basename[:-4]

    zip_filename = zip_basename + ".zip"
    zip_path = os.path.join(objects_dir, zip_filename)

    if os.path.exists(zip_path):
        raise RuntimeError(f"Zip file already exists: {zip_path}")

    print("\nZipping directory...")
    print(f"  Source (package root): {package_dir}")
    print(f"  Zip output:            {zip_path}\n")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(package_dir):
            # Do not include objects/ itself in the zip.
            rel_from_pkg = os.path.relpath(root, package_dir)
            if "objects" in dirs:
                dirs.remove("objects")

            rel_root = os.path.relpath(root, parent_of_package)

            # Empty dirs
            if not files and not dirs:
                arcdir = rel_root.rstrip("/") + "/"
                zf.writestr(arcdir, "")
                print(f"  [dir]  {arcdir}")
                continue

            for name in files:
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, parent_of_package)
                print(f"  [file] {rel_path}")
                zf.write(full_path, arcname=rel_path)

    print("\nZipping complete.")
    return zip_path

def rsync_into_objects(package_dir: str, objects_dir: str):
    """
    Use rsync to copy everything from package_dir/ into objects_dir,
    excluding objects/ itself.
    """
    package_dir = os.path.normpath(package_dir)
    objects_dir = os.path.normpath(objects_dir)

    # Ensure the destination exists so rsync doesn't get confused,
    # especially when paths contain spaces.
    os.makedirs(objects_dir, exist_ok=True)

    print("\nCopying contents into objects/ using rsync...")
    print(f"  From: {package_dir}/")
    print(f"  To:   {objects_dir}\n")

    # Explicit trailing slash behavior
    src_with_slash = package_dir + os.sep
    dest_with_slash = objects_dir + os.sep

    try:
        subprocess.run(
            [
                "rsync",
                "-av",
                "--exclude",
                "objects/",
                src_with_slash,
                dest_with_slash,
            ],
            check=True,
        )
    except FileNotFoundError:
        raise RuntimeError("rsync not found. Please install rsync and try again.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"rsync failed with exit code {e.returncode}")

def delete_non_objects_in_root(package_dir: str):
    """
    Delete everything in package_dir EXCEPT the objects/ directory.
    Use carefully!
    """
    for name in os.listdir(package_dir):
        if name == "objects":
            continue
        full_path = os.path.join(package_dir, name)
        if os.path.isdir(full_path):
            print(f"  Removing directory: {full_path}")
            shutil.rmtree(full_path)
        else:
            print(f"  Removing file:      {full_path}")
            os.remove(full_path)

def main():
    print("\n=== PACKAGE + OPTIONAL ZIP + OBJECTS FOLDER ===\n")

    # 1) Get directory to package
    package_dir = normalize_path(
        input("Enter or drag the DIRECTORY to package: ")
    )
    if not package_dir or not os.path.isdir(package_dir):
        print("ERROR: That path is not a valid directory.")
        return

    parent_dir = os.path.dirname(package_dir)
    current_name = os.path.basename(os.path.normpath(package_dir))

    print(f"\nCurrent directory name: {current_name}")
    print(f"Full path:              {package_dir}")

    # 2) Optional rename of the directory
    new_name_in = input(
        f"New PACKAGE NAME (directory name) "
        f"[press Enter to keep '{current_name}']: "
    ).strip()

    if new_name_in and new_name_in != current_name:
        new_path = os.path.join(parent_dir, new_name_in)

        if os.path.exists(new_path):
            print(f"\nERROR: A directory already exists at:\n  {new_path}")
            print("Choose a different package name or rename manually.")
            return

        print(f"\nRenaming directory:\n  {package_dir}\n-> {new_path}\n")
        try:
            os.rename(package_dir, new_path)
        except OSError as e:
            print(f"ERROR: Could not rename directory: {e}")
            return

        package_dir = new_path
        current_name = new_name_in
        print("Rename complete.")
    else:
        print("\nKeeping existing directory name.")

    # Ensure objects directory
    objects_dir = os.path.join(package_dir, "objects")
    os.makedirs(objects_dir, exist_ok=True)
    print(f"\nUsing objects directory:\n  {objects_dir}")

    # 3) Ask whether to zip
    zip_choice = input(
        "\nDo you want to create a ZIP of this directory and put the ZIP in objects/? [Y/n]: "
    ).strip().lower()

    if zip_choice in ("", "y", "yes"):
        # ZIP MODE: create a zip in objects/
        default_zip_base = current_name
        zip_base_in = input(
            f"Zip filename (without .zip) [{default_zip_base}]: "
        ).strip()
        zip_basename = zip_base_in or default_zip_base

        try:
            zip_path = zip_directory_into_objects(package_dir, objects_dir, zip_basename)
        except Exception as e:
            print(f"ERROR while zipping: {e}")
            return

        # NEW: optionally delete the original files that were just zipped
        delete_choice = input(
            "\nDo you want to delete the original files/directories from the package root,\n"
            "now that they are contained in the ZIP (leaving only 'objects/' at top level)? [y/N]: "
        ).strip().lower()

        if delete_choice in ("y", "yes"):
            print("\nDeleting original contents from package root (except 'objects/')...")
            delete_non_objects_in_root(package_dir)
            print("Cleanup complete.")
        else:
            print("\nKeeping original contents in the package root.")

        print("\n=== DONE (ZIP MODE) ===")
        print(f"Package directory: {package_dir}")
        print(f"Objects directory: {objects_dir}")
        print(f"Zip file created:  {zip_path}")
        print("Next steps: create_manifest.py, then send_to_sftp.py / send_to_azure.py")
        return

    # NO-ZIP MODE: use rsync to put all contents into objects/
    print("\nSkipping ZIP creation. Contents will be copied into objects/.")

    try:
        rsync_into_objects(package_dir, objects_dir)
    except Exception as e:
        print(f"ERROR while rsync'ing into objects/: {e}")
        return

    # Optionally delete originals from root
    delete_choice = input(
        "\nDo you want to delete the original files/directories from the package root,\n"
        "leaving only the 'objects' folder at the top level? [y/N]: "
    ).strip().lower()

    if delete_choice in ("y", "yes"):
        print("\nDeleting original contents from package root (except 'objects/')...")
        delete_non_objects_in_root(package_dir)
        print("Cleanup complete.")
    else:
        print("\nKeeping original contents in the package root (you now have duplicates in objects/).")

    print("\n=== DONE (NO-ZIP MODE) ===")
    print(f"Package directory: {package_dir}")
    print(f"Objects directory: {objects_dir}")
    print("Next steps: create_manifest.py, then send_to_sftp.py / send_to_azure.py")

if __name__ == "__main__":
    main()
