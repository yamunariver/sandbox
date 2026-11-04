I'll check how Dangerzone handles its container image offline, because that's the part that usually breaks air-gapped installs.

I'm taking "air gap" to mean the target server can't reach the internet. Your server could reach the Ubuntu archive earlier today, so if this is the machine that still has internet access, my previous answer is simpler. For a truly offline server the problem is the same dependency list, plus Dangerzone's container image. There are three steps: ask the offline server which packages it's missing, download them on a connected machine, then install them offline.

## 1. On the offline server: list what's missing

The server knows its own package state, so it can say exactly which `.deb` files it needs, including the dependencies of Dangerzone's unconfigured install:

```bash
sudo apt-get -y -qq --print-uris --fix-broken install > uris.txt
wc -l uris.txt
grep -c '^.http' uris.txt
```

Look at the list, especially the `Remv` risk I mentioned earlier. Printing URIs changes nothing, so it's safe. Then make a checksum file:

```bash
grep "^'http" uris.txt | sed -E "s/^'[^']+' ([^ ]+) [0-9]+ SHA256:([0-9a-f]+).*/\2  \1/" > SHA256SUMS
grep "^'http" uris.txt | grep -o "http[^']*" > urls.txt
```

Copy `urls.txt` and `SHA256SUMS` to the connected machine.

## 2. On a connected machine: download and verify

Any machine with `wget` will do. It doesn't need to run Ubuntu 22.04, because it only fetches files by URL:

```bash
mkdir dz-debs && cd dz-debs
wget -i ../urls.txt
sha256sum -c ../SHA256SUMS
```

Every line should say `OK`. A 404 means the offline server's package lists are older than the archive (Ubuntu removes superseded versions). In that case, update the lists on a connected 22.04 machine and redo step 1 there instead, or tell me and I'll give you the recursive-download method.

Expect a large download. `tesseract-ocr-all` pulls OCR data for every language.

## 3. On the offline server: install from the cache

Copy the `.deb` files over by your approved media, and check the checksums again on arrival. Then:

```bash
sudo cp *.deb /var/cache/apt/archives/
sudo apt-get install --no-download -y --fix-broken
```

`--no-download` makes `apt` fail instead of reaching for the network, so you know nothing is being fetched. Then check:

```bash
dpkg -l dangerzone | tail -1
```

You want `ii`.

## 4. The container image

Dangerzone converts documents inside a container. I believe the 0.11.1 `.deb` ships its own image and loads it, but I haven't confirmed that, so check:

```bash
podman images | grep -i dangerzone
```

If nothing is listed, the image has to be carried across too. Dangerzone's developer docs describe a signed archive for air-gapped installs. On a connected machine that has Dangerzone installed:

```bash
dangerzone-image prepare-archive --output dz-image.tar
```

On the offline server:

```bash
dangerzone-image load-archive dz-image.tar
```

The docs I found show these commands in the form `prepare-archive --output FILE IMAGE@sha256:<digest>`. Run `dangerzone-image --help` and `dangerzone-image prepare-archive --help` to confirm the exact flags for 0.11.1. Use the signed archive and don't save the image with plain `podman save` and load it. Dangerzone checks signatures, and a plain image may be refused.

## Two cautions

- **Where to install it:** I'd put Dangerzone on a separate workstation and not on the CAPE host. It brings in Podman, with its own container networking, and your CAPE host's isolation is exactly what you want to keep simple. If you do install it there, re-run the `tcpdump` isolation test on the next analysis.
- **Anything crossing the air gap** should be checked with the checksums above, plus whatever your organisation's transfer procedure requires.

Paste `uris.txt` if the list shows `Remv` lines or a surprisingly long list, and paste the error if step 3 fails.
