# GitVault: iPhone photo & video backup to GitHub

A web app that saves the photos and videos from your iPhone into a **private GitHub repository** you own. You can browse, play, and download them from any browser. It is password-protected and needs no server: the app talks to GitHub directly from your browser.

## Features
- **Upload** from your iPhone photo library (HEIC, JPEG, PNG, MOV, MP4…). Original files are kept untouched.
- **Timeline** grouped by month, using the real capture date read from the photo (EXIF) or video (QuickTime) metadata.
- **Large videos:** files over 45 MB are split into parts automatically, because GitHub rejects any single file over 100 MB. They are joined again when you play or download them.
- **No duplicates:** a photo you've already backed up is skipped.
- **Thumbnails** are made on the phone during upload, so the gallery loads quickly.
- **App password:** your GitHub token is stored on the device encrypted with your password (AES-256-GCM, key from PBKDF2-SHA256 with 310,000 iterations). The app auto-locks after 10 minutes of inactivity and has a manual **Lock** button.
- **Save back to the phone:** on iPhone, Download opens the share sheet, so you can choose *Save Image* or *Save Video*.
- Can be installed on the iPhone home screen like a normal app.

## Setup (about 5 minutes)

### 1. Create the storage repository
On github.com → **New repository**, for example `my-photos`, set to **Private**. You can leave it empty.

### 2. Create a token for the app
GitHub → Settings → Developer settings → **Fine-grained tokens** → *Generate new token*:
- **Repository access:** *Only select repositories* → `my-photos`
- **Permissions → Repository → Contents:** *Read and write*
- Pick an expiration date you're comfortable with. When the token expires, the app asks for a new one.

### 3. Host the app (free, on GitHub Pages)
1. Create a second repository (it can be public, because it only holds the app code and none of your photos), for example `gitvault`.
2. Upload the files from this folder to it.
3. In that repository go to **Settings → Pages → Deploy from a branch → `main` / root**.
4. After a minute the app is live at `https://<your-username>.github.io/gitvault/`.

### 4. Install it on your iPhone
Open that link in **Safari** → **Share** → **Add to Home Screen**. Open it from the home screen, then enter your token, the `your-username/my-photos` repository, and choose an app password.

## Good to know
- **Keep the app open while uploading.** iPhone browsers pause web pages in the background. The app keeps the screen awake while uploading.
- **Repository size:** GitHub recommends keeping repositories under about 5 GB. The app warns you when you get close; then start a new repository, for example one per year.
- **Deleting** removes a photo from the album, but Git keeps it in the repository's history, so the repository size does not go down.
- **Forgot the app password?** Tap *Forgot password?* on the lock screen, then enter your token again and choose a new password. Your photos are not affected.
- **Who can see your photos:** you, and anyone you give access to the private repository. The photos are not encrypted on GitHub's servers. The app password protects access *from this device*.
- **On a computer:** Chrome can't display HEIC photos (Safari can), but they still download fine.

## Repository layout
```
media/2024/03/20240302-101112_IMG_0003.MOV          original files, named by capture date
media/2026/11/20261110-072743_IMG_0005.MOV.parts/   large videos split into parts
thumbs/...                                         small previews used by the gallery
```
To rebuild a split video by hand: `cat part-* > IMG_0005.MOV`
