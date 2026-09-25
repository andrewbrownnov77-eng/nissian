# Installing the Garand desktop icon

This session runs in the cloud, so it can't touch your real desktop. Install
locally with one of the following on your own machine.

## Linux (GNOME/KDE/XFCE)
```bash
# from the repo root
install -Dm644 assets/garand-256.png ~/.local/share/icons/garand.png
install -Dm644 assets/garand.desktop  ~/.local/share/applications/garand.desktop
update-desktop-database ~/.local/share/applications 2>/dev/null || true
# to also drop it on the desktop:
cp assets/garand.desktop ~/Desktop/ && chmod +x ~/Desktop/garand.desktop
```

## macOS
Use `assets/garand-512.png` as the icon: open it in Preview, Select All, Copy,
then Get Info (⌘I) on a `garand` script/app and paste onto the icon well.

## Windows
Create a shortcut to your `garand` launcher, then Properties → Change Icon →
point at a `.ico` built from `assets/garand-256.png`.
