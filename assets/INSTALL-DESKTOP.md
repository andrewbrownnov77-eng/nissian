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

## Windows 11 (automatic)
A ready-made multi-resolution icon (`garand.ico`), a launcher (`garand.cmd`),
and an installer script are included. From the repo root in PowerShell:

```powershell
# one-time, if not already done: install Node.js, then
npm install; npm run build

# create the desktop shortcut with the Garand icon
powershell -ExecutionPolicy Bypass -File assets\install-windows.ps1
```

This drops **Garand.lnk** on your desktop, pointing at `assets\garand.cmd`
with `assets\garand.ico` as the icon. Double-clicking opens a terminal running
the CLI (append args by editing the shortcut Target, e.g. `... discover ...`).

## Windows 11 (manual)
Right-click desktop → New → Shortcut → location `…\assets\garand.cmd` →
name it *Garand* → Finish. Then right-click it → Properties → Change Icon →
Browse to `…\assets\garand.ico`.
