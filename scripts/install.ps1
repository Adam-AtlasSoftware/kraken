<#
.SYNOPSIS
Installs, reinstalls or removes KRAKEN for the current Windows user. No administrator rights.

.DESCRIPTION
One command, in Windows PowerShell 5.1 or PowerShell 7:

    irm https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.ps1 | iex

With options (a piped script takes no parameters, so make it a script block first):

    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.ps1))) -Version v0.4.1
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.ps1))) -Uninstall

Or save the file and run `powershell -ExecutionPolicy Bypass -File install.ps1 [options]`.
KRAKEN_VERSION, KRAKEN_INSTALL_DIR and KRAKEN_PROXY in the environment stand in for -Version,
-InstallDir and -Proxy.

What it writes, and nothing else:
  - the programs in %LOCALAPPDATA%\Programs\KRAKEN (bin\, share\kraken\, docs\, licenses\),
  - the install receipt share\kraken\install.json there, which tells `kraken update` that this
    script installed KRAKEN, so KRAKEN can update itself in place,
  - that bin folder at the end of the user's Path (HKCU\Environment), unless it is there already,
  - a Start Menu shortcut, Programs\KRAKEN\KRAKEN.lnk.
-Uninstall removes exactly those (it reads the receipt to know what it added). Your projects,
settings and downloaded engines stay unless you add -Purge.

How the download is trusted:
  1. This script comes from the KRAKEN repository over HTTPS, and it embeds the release public key
     (minisign, key id E9CBFBBF6ECFB91C; the same key as scripts/install.sh and the key compiled
     into kraken.exe).
  2. Each release publishes SHA256SUMS and SHA256SUMS.minisig, signed with the matching secret key
     by the release workflow. The script checks that signature first, with the Ed25519 and
     BLAKE2b-512 code below (Windows PowerShell 5.1 has neither built in), and checks that its
     trusted comment is exactly "kraken v<version> SHA256SUMS", so an old signed list cannot be
     passed off as a newer release.
  3. The zip must then have the SHA-256 the signed list gives for it. Only then is it unpacked.
  4. Later updates (`kraken update`) check the same signature with the key compiled into KRAKEN.
A compromised release page or download server therefore cannot get a file installed without the
signing key. Release files also carry GitHub build provenance attestations, which you can check
yourself with `gh attestation verify <zip> --repo Adam-AtlasSoftware/kraken`.
#>
param(
    # Release tag to install (vX.Y.Z); the newest release when empty.
    [string]$Version = '',
    # Where to install; %LOCALAPPDATA%\Programs\KRAKEN when empty.
    [string]$InstallDir = '',
    # Removes what this script installed.
    [switch]$Uninstall,
    # With -Uninstall: also removes KRAKEN's data folder (downloaded engines, caches, kept versions).
    [switch]$Purge,
    # Leaves the user's Path alone.
    [switch]$NoPath,
    # Creates no Start Menu shortcut.
    [switch]$NoShortcut,
    # Stops running KRAKEN programs without asking, installs over a folder without a receipt, and
    # tries the x86-64 build on an ARM64 computer.
    [switch]$Force,
    # Proxy URL; the system proxy settings otherwise.
    [string]$Proxy = ''
)

$KrakenRepo = 'Adam-AtlasSoftware/kraken'
$KrakenTarget = 'x86_64-pc-windows-msvc'
$KrakenPublicKey = 'RWQcuc9uv/vL6fNGCFoY+ea132bmfUHhfczZGY/UgdNbC08hjU6DYmln'
$KrakenPrograms = @('kraken-gui', 'krakend', 'kraken', 'kraken-native-worker', 'kraken-emu-run')
# Empty when the script was piped (`irm | iex`) rather than run from a file.
$KrakenScriptPath = [string](Get-Variable -Name PSCommandPath -ValueOnly -ErrorAction SilentlyContinue)

# BEGIN VERIFIER (C# 5, so the .NET Framework compiler of PowerShell 5.1 builds it)
$KrakenVerifierSource = @'
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace KrakenInstall
{
    // BLAKE2b-512 without a key (RFC 7693).
    public static class Blake2b
    {
        static readonly ulong[] IV = {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL };
        static readonly byte[,] Sigma = {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 } };

        static ulong Rotr(ulong x, int n) { return (x >> n) | (x << (64 - n)); }

        static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
        {
            v[a] = v[a] + v[b] + x; v[d] = Rotr(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d]; v[b] = Rotr(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y; v[d] = Rotr(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d]; v[b] = Rotr(v[b] ^ v[c], 63);
        }

        static void Compress(ulong[] h, byte[] block, ulong t, bool last)
        {
            if (!BitConverter.IsLittleEndian) throw new PlatformNotSupportedException();
            ulong[] m = new ulong[16];
            for (int i = 0; i < 16; i++) m[i] = BitConverter.ToUInt64(block, i * 8);
            ulong[] v = new ulong[16];
            for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = IV[i]; }
            v[12] ^= t;
            if (last) v[14] = ~v[14];
            for (int r = 0; r < 12; r++)
            {
                int s = r % 10;
                G(v, 0, 4, 8, 12, m[Sigma[s, 0]], m[Sigma[s, 1]]);
                G(v, 1, 5, 9, 13, m[Sigma[s, 2]], m[Sigma[s, 3]]);
                G(v, 2, 6, 10, 14, m[Sigma[s, 4]], m[Sigma[s, 5]]);
                G(v, 3, 7, 11, 15, m[Sigma[s, 6]], m[Sigma[s, 7]]);
                G(v, 0, 5, 10, 15, m[Sigma[s, 8]], m[Sigma[s, 9]]);
                G(v, 1, 6, 11, 12, m[Sigma[s, 10]], m[Sigma[s, 11]]);
                G(v, 2, 7, 8, 13, m[Sigma[s, 12]], m[Sigma[s, 13]]);
                G(v, 3, 4, 9, 14, m[Sigma[s, 14]], m[Sigma[s, 15]]);
            }
            for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
        }

        public static byte[] Hash512(byte[] data)
        {
            ulong[] h = (ulong[])IV.Clone();
            h[0] ^= 0x01010000UL ^ 64UL;
            byte[] block = new byte[128];
            int off = 0;
            ulong t = 0;
            // Every full block but the final one is compressed as "not last".
            while (data.Length - off > 128)
            {
                Buffer.BlockCopy(data, off, block, 0, 128);
                t += 128;
                Compress(h, block, t, false);
                off += 128;
            }
            Array.Clear(block, 0, 128);
            int rest = data.Length - off;
            Buffer.BlockCopy(data, off, block, 0, rest);
            t += (ulong)rest;
            Compress(h, block, t, true);
            byte[] outb = new byte[64];
            for (int i = 0; i < 8; i++) Buffer.BlockCopy(BitConverter.GetBytes(h[i]), 0, outb, i * 8, 8);
            return outb;
        }
    }

    // Ed25519 signature verification only (RFC 8032, section 5.1.7), over extended coordinates.
    // It handles public data only, so constant time does not matter here.
    public static class Ed25519
    {
        static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
        static readonly BigInteger D = Mod(-121665 * Inv(121666));
        static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);
        static readonly BigInteger[] B = MakeBase();

        static BigInteger Mod(BigInteger x) { BigInteger r = x % P; return r.Sign < 0 ? r + P : r; }
        static BigInteger Inv(BigInteger x) { return BigInteger.ModPow(Mod(x), P - 2, P); }

        static BigInteger[] MakeBase()
        {
            BigInteger y = Mod(4 * Inv(5));
            BigInteger x = RecoverX(y, 0);
            return new BigInteger[] { x, y, BigInteger.One, Mod(x * y) };
        }

        // x for y with the given low bit, or -1 when there is none.
        static BigInteger RecoverX(BigInteger y, int sign)
        {
            if (y >= P) return BigInteger.MinusOne;
            BigInteger x2 = Mod((y * y - 1) * Inv(D * y * y + 1));
            if (x2.IsZero) return sign == 0 ? BigInteger.Zero : BigInteger.MinusOne;
            BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
            if (Mod(x * x - x2) != 0) x = Mod(x * I);
            if (Mod(x * x - x2) != 0) return BigInteger.MinusOne;
            if ((int)(x % 2) != sign) x = P - x;
            return x;
        }

        static BigInteger[] Add(BigInteger[] p, BigInteger[] q)
        {
            BigInteger a = Mod((p[1] - p[0]) * (q[1] - q[0]));
            BigInteger b = Mod((p[1] + p[0]) * (q[1] + q[0]));
            BigInteger c = Mod(2 * p[3] * q[3] * D);
            BigInteger d = Mod(2 * p[2] * q[2]);
            BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
            return new BigInteger[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
        }

        static BigInteger[] Mul(BigInteger s, BigInteger[] p)
        {
            BigInteger[] q = new BigInteger[] { BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero };
            while (s.Sign > 0)
            {
                if (!s.IsEven) q = Add(q, p);
                p = Add(p, p);
                s >>= 1;
            }
            return q;
        }

        static BigInteger FromLe(byte[] b, int off, int len)
        {
            byte[] t = new byte[len + 1];
            Buffer.BlockCopy(b, off, t, 0, len);
            return new BigInteger(t);
        }

        static byte[] Encode(BigInteger[] p)
        {
            BigInteger zi = Inv(p[2]);
            BigInteger x = Mod(p[0] * zi), y = Mod(p[1] * zi);
            byte[] raw = y.ToByteArray();
            byte[] outb = new byte[32];
            Buffer.BlockCopy(raw, 0, outb, 0, Math.Min(raw.Length, 32));
            if (!x.IsEven) outb[31] |= 0x80;
            return outb;
        }

        static BigInteger[] Decode(byte[] b, int off)
        {
            byte[] t = new byte[32];
            Buffer.BlockCopy(b, off, t, 0, 32);
            int sign = t[31] >> 7;
            t[31] &= 0x7f;
            BigInteger y = FromLe(t, 0, 32);
            BigInteger x = RecoverX(y, sign);
            if (x.Sign < 0) return null;
            return new BigInteger[] { x, y, BigInteger.One, Mod(x * y) };
        }

        public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null || publicKey.Length != 32 || signature == null || signature.Length != 64 || message == null)
                return false;
            BigInteger[] a = Decode(publicKey, 0);
            if (a == null) return false;
            if (Decode(signature, 0) == null) return false;
            BigInteger s = FromLe(signature, 32, 32);
            if (s >= L) return false;
            byte[] buf = new byte[64 + message.Length];
            Buffer.BlockCopy(signature, 0, buf, 0, 32);
            Buffer.BlockCopy(publicKey, 0, buf, 32, 32);
            Buffer.BlockCopy(message, 0, buf, 64, message.Length);
            byte[] hash;
            using (SHA512 sha = SHA512.Create()) { hash = sha.ComputeHash(buf); }
            BigInteger h = FromLe(hash, 0, 64) % L;
            // [s]B - [h]A must encode to R exactly.
            BigInteger[] ha = Mul(h, a);
            BigInteger[] neg = new BigInteger[] { Mod(-ha[0]), ha[1], ha[2], Mod(-ha[3]) };
            byte[] r = Encode(Add(Mul(s, B), neg));
            for (int i = 0; i < 32; i++) if (r[i] != signature[i]) return false;
            return true;
        }
    }

    // The minisign check of the updater (crates/kraken-host/src/update/verify.rs): prehashed
    // ("ED") signatures only, the key id must match, the global signature covers the signature and
    // the trusted comment, and the trusted comment must be exactly the expected one.
    public static class Minisign
    {
        // Empty when valid, else the reason.
        public static string Check(byte[] data, string sigText, string publicKeyB64, string expectedComment)
        {
            byte[] pk;
            try { pk = Convert.FromBase64String(publicKeyB64.Trim()); }
            catch (FormatException) { return "the embedded public key is not base64"; }
            if (pk.Length != 42 || pk[0] != (byte)'E' || pk[1] != (byte)'d') return "the embedded public key is not a minisign Ed25519 key";

            string[] lines = sigText.Replace("\r\n", "\n").Split('\n');
            if (lines.Length < 4) return "SHA256SUMS.minisig is not a minisign signature";
            if (!lines[0].StartsWith("untrusted comment:")) return "SHA256SUMS.minisig has no untrusted comment line";
            const string tcPrefix = "trusted comment: ";
            if (!lines[2].StartsWith(tcPrefix)) return "SHA256SUMS.minisig has no trusted comment line";
            byte[] sig, global;
            try
            {
                sig = Convert.FromBase64String(lines[1].Trim());
                global = Convert.FromBase64String(lines[3].Trim());
            }
            catch (FormatException) { return "SHA256SUMS.minisig is not valid base64"; }
            if (sig.Length != 74 || global.Length != 64) return "SHA256SUMS.minisig has the wrong length";
            if (sig[0] != (byte)'E' || sig[1] != (byte)'D') return "SHA256SUMS.minisig is not a prehashed (ED) signature";
            for (int i = 0; i < 8; i++)
                if (sig[2 + i] != pk[2 + i]) return "SHA256SUMS was signed by another key";

            byte[] key = new byte[32];
            Buffer.BlockCopy(pk, 10, key, 0, 32);
            byte[] edSig = new byte[64];
            Buffer.BlockCopy(sig, 10, edSig, 0, 64);
            if (!Ed25519.Verify(key, Blake2b.Hash512(data), edSig))
                return "SHA256SUMS is not signed by the KRAKEN release key";

            string comment = lines[2].Substring(tcPrefix.Length);
            byte[] commentBytes = Encoding.UTF8.GetBytes(comment);
            byte[] signed = new byte[64 + commentBytes.Length];
            Buffer.BlockCopy(edSig, 0, signed, 0, 64);
            Buffer.BlockCopy(commentBytes, 0, signed, 64, commentBytes.Length);
            if (!Ed25519.Verify(key, signed, global))
                return "the trusted comment of SHA256SUMS.minisig is not signed by the KRAKEN release key";
            if (comment != expectedComment)
                return "the signature is for \"" + comment + "\", not \"" + expectedComment + "\"";
            return "";
        }
    }
}
'@
# END VERIFIER

function Write-Step([string]$Text) { Write-Host "==> $Text" }
function Write-Note([string]$Text) { Write-Host "    $Text" }

# Runs $Action, retrying a few times while a file is busy (antivirus scanning a new file, an
# indexer, a program that is still closing).
function Invoke-Retrying([scriptblock]$Action, [string]$What) {
    $delays = @(200, 500, 1000, 2000, 3000, 5000)
    for ($i = 0; ; $i++) {
        try {
            return (& $Action)
        } catch {
            $busy = $_.Exception -is [System.IO.IOException] -or
                $_.Exception -is [System.UnauthorizedAccessException] -or
                $_.Exception.InnerException -is [System.IO.IOException] -or
                $_.Exception.InnerException -is [System.UnauthorizedAccessException]
            if (-not $busy -or $i -ge $delays.Count) {
                throw "$What failed: $($_.Exception.Message)"
            }
            Start-Sleep -Milliseconds $delays[$i]
        }
    }
}

function Move-Retrying([string]$From, [string]$To) {
    Invoke-Retrying { [System.IO.Directory]::Move($From, $To) } "Moving $From to $To" | Out-Null
}

# Deletes a folder; $false (and the folder left in place) when something still holds a file.
function Remove-Folder([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    try {
        Invoke-Retrying { [System.IO.Directory]::Delete($Path, $true) } "Removing $Path" | Out-Null
        return $true
    } catch {
        return $false
    }
}

# A property of a parsed JSON object, or $null when it lacks it (StrictMode-safe).
function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-FullPath([string]$Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-SamePath([string]$A, [string]$B) {
    if (-not $A -or -not $B) { return $false }
    try {
        $a2 = Get-FullPath ([Environment]::ExpandEnvironmentVariables($A.Trim().Trim('"')))
        $b2 = Get-FullPath ([Environment]::ExpandEnvironmentVariables($B.Trim().Trim('"')))
    } catch {
        return $false
    }
    return [string]::Equals($a2, $b2, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-Under([string]$Path, [string]$Dir) {
    if (-not $Path) { return $false }
    try { $p = Get-FullPath $Path } catch { return $false }
    $d = (Get-FullPath $Dir) + '\'
    return $p.StartsWith($d, [System.StringComparison]::OrdinalIgnoreCase)
}

# The data folder KRAKEN uses on Windows (`llama_setup::data_dir_with`): XDG_DATA_HOME, then
# %LOCALAPPDATA%\kraken, then HOME (only when there is no LOCALAPPDATA).
function Get-KrakenDataDir {
    if ($env:XDG_DATA_HOME -and [System.IO.Path]::IsPathRooted($env:XDG_DATA_HOME)) {
        return (Join-Path $env:XDG_DATA_HOME 'kraken')
    }
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    if ($local) { return (Join-Path $local 'kraken') }
    if ($env:HOME) { return (Join-Path $env:HOME '.local\share\kraken') }
    return $null
}

# The settings folder on Windows (`KrakenConfig::default_path`): XDG_CONFIG_HOME, then
# %APPDATA%\kraken, then HOME.
function Get-KrakenConfigDir {
    if ($env:XDG_CONFIG_HOME -and [System.IO.Path]::IsPathRooted($env:XDG_CONFIG_HOME)) {
        return (Join-Path $env:XDG_CONFIG_HOME 'kraken')
    }
    $roaming = [Environment]::GetFolderPath('ApplicationData')
    if ($roaming) { return (Join-Path $roaming 'kraken') }
    if ($env:HOME) { return (Join-Path $env:HOME '.config\kraken') }
    return $null
}

function Get-InstallDir {
    if ($InstallDir) { return (Get-FullPath $InstallDir) }
    if ($env:KRAKEN_INSTALL_DIR) { return (Get-FullPath $env:KRAKEN_INSTALL_DIR) }
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not $local) { throw 'Cannot find your local application data folder (%LOCALAPPDATA%).' }
    return (Join-Path $local 'Programs\KRAKEN')
}

function Read-Receipt([string]$Prefix) {
    $file = Join-Path $Prefix 'share\kraken\install.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $null }
    try {
        $text = [System.IO.File]::ReadAllText($file)
        if ($text.Length -gt 65536) { return $null }
        $r = $text | ConvertFrom-Json
        if ((Get-Prop $r 'method') -ne 'windows_installer') { return $null }
        return $r
    } catch {
        return $null
    }
}

function Write-Receipt([string]$Prefix, [string]$Ver, [bool]$PathAdded, [string]$Shortcut) {
    $r = [ordered]@{
        method     = 'windows_installer'
        version    = $Ver
        prefix     = $Prefix
        path_added = $PathAdded
        shortcut   = $Shortcut
    }
    $json = (New-Object PSObject -Property $r) | ConvertTo-Json
    $file = Join-Path $Prefix 'share\kraken\install.json'
    [System.IO.File]::WriteAllText($file, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

# --- network -----------------------------------------------------------------------------------

function Initialize-Network {
    # Windows PowerShell 5.1 may still default to TLS 1.0; GitHub needs 1.2.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        # The system proxy, signed in as the person (an authenticating corporate proxy).
        $sys = [System.Net.WebRequest]::GetSystemWebProxy()
        $sys.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        [System.Net.WebRequest]::DefaultWebProxy = $sys
    }
}

# Proxy arguments for Invoke-WebRequest: -Proxy, KRAKEN_PROXY, HTTPS_PROXY, else the system proxy
# for this address (PowerShell 7 ignores DefaultWebProxy, so it is named explicitly).
function Get-ProxyArgs([string]$Uri) {
    $explicit = $Proxy
    if (-not $explicit) { $explicit = $env:KRAKEN_PROXY }
    if (-not $explicit) { $explicit = $env:HTTPS_PROXY }
    if (-not $explicit) { $explicit = $env:https_proxy }
    if ($explicit) {
        return @{ Proxy = $explicit; ProxyUseDefaultCredentials = $true }
    }
    try {
        $target = New-Object System.Uri($Uri)
        $via = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($target)
        if ($via -and $via.AbsoluteUri -ne $target.AbsoluteUri) {
            return @{ Proxy = $via.AbsoluteUri; ProxyUseDefaultCredentials = $true }
        }
    } catch { }
    return @{}
}

function Invoke-Download([string]$Uri, [string]$OutFile) {
    $proxyArgs = Get-ProxyArgs $Uri
    $headers = @{ 'User-Agent' = 'kraken-install-ps1' }
    for ($i = 1; ; $i++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -Headers $headers @proxyArgs
            return
        } catch {
            if ($i -ge 3) { throw "Download of $Uri failed: $($_.Exception.Message)" }
            Start-Sleep -Seconds (2 * $i)
        }
    }
}

function Get-LatestVersion {
    $api = "https://api.github.com/repos/$KrakenRepo/releases/latest"
    try {
        $apiProxy = Get-ProxyArgs $api
        $resp = Invoke-WebRequest -Uri $api -UseBasicParsing -Headers @{ 'User-Agent' = 'kraken-install-ps1'; 'Accept' = 'application/vnd.github+json' } @apiProxy
        $tag = Get-Prop ($resp.Content | ConvertFrom-Json) 'tag_name'
        if ($tag) { return [string]$tag }
    } catch {
        Write-Note "The GitHub API did not answer ($($_.Exception.Message)); asking the releases page."
    }
    # The releases page redirects /latest to /tag/<tag> (no API rate limit).
    $page = "https://github.com/$KrakenRepo/releases/latest"
    $proxyArgs = Get-ProxyArgs $page
    $resp = Invoke-WebRequest -Uri $page -UseBasicParsing -Method Head -Headers @{ 'User-Agent' = 'kraken-install-ps1' } @proxyArgs
    $final = $null
    if ($resp.BaseResponse.PSObject.Properties['ResponseUri']) { $final = $resp.BaseResponse.ResponseUri }
    elseif ($resp.BaseResponse.PSObject.Properties['RequestMessage']) { $final = $resp.BaseResponse.RequestMessage.RequestUri }
    if ($final -and $final.AbsolutePath -match '/releases/tag/([^/]+)$') { return $Matches[1] }
    throw 'Cannot tell which release is the newest; pass -Version vX.Y.Z.'
}

# --- signature ---------------------------------------------------------------------------------

function Initialize-Verifier {
    if ('KrakenInstall.Minisign' -as [type]) { return }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -TypeDefinition $KrakenVerifierSource -Language CSharp
    } else {
        Add-Type -AssemblyName System.Numerics
        $numerics = [System.Numerics.BigInteger].Assembly.Location
        Add-Type -TypeDefinition $KrakenVerifierSource -Language CSharp -ReferencedAssemblies $numerics
    }
}

# Fails unless SHA256SUMS carries a valid release signature for $Ver.
function Test-ReleaseSignature([string]$Sums, [string]$Sig, [string]$Ver) {
    Initialize-Verifier
    $data = [System.IO.File]::ReadAllBytes($Sums)
    $sigText = [System.IO.File]::ReadAllText($Sig)
    $why = [KrakenInstall.Minisign]::Check($data, $sigText, $KrakenPublicKey, "kraken v$Ver SHA256SUMS")
    if ($why) { throw "Signature check failed: $why. Nothing was installed." }
}

# The SHA-256 the list gives for exactly $Name (sha256sum format), lower case.
function Get-SumFor([string]$Sums, [string]$Name) {
    foreach ($line in [System.IO.File]::ReadAllLines($Sums)) {
        if ($line -match '^([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -ceq $Name) {
            return $Matches[1].ToLowerInvariant()
        }
    }
    return $null
}

# --- files -------------------------------------------------------------------------------------

# Unpacks the release zip's top folder into $Dest, refusing entries that are absolute, climb with
# `..` or land outside it.
function Expand-Release([string]$Zip, [string]$Dest, [string]$Top) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $root = (Get-FullPath $Dest) + '\'
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $plan = @()
        foreach ($e in $archive.Entries) {
            $name = $e.FullName.Replace('\', '/')
            if ($name.StartsWith('/') -or $name.Contains(':') -or ($name.Split('/') -contains '..')) {
                throw "The release zip holds an unsafe path ($($e.FullName)); nothing was installed."
            }
            if (-not $name.StartsWith("$Top/")) {
                throw "The release zip holds $($e.FullName) outside $Top; nothing was installed."
            }
            $rel = $name.Substring($Top.Length + 1)
            if (-not $rel) { continue }
            $target = [System.IO.Path]::GetFullPath((Join-Path $root $rel.Replace('/', '\')))
            if (-not $target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "The release zip holds $($e.FullName), which would land outside the install; nothing was installed."
            }
            if ($target.Length -ge 260 -and $PSVersionTable.PSEdition -ne 'Core') {
                throw "The install path is too long for Windows PowerShell ($target). Install somewhere shorter with -InstallDir, for example C:\KRAKEN."
            }
            $plan += , @($e, $target, $name.EndsWith('/'))
        }
        foreach ($p in $plan) {
            if ($p[2]) {
                [System.IO.Directory]::CreateDirectory($p[1]) | Out-Null
            } else {
                [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($p[1])) | Out-Null
                $entry = $p[0]; $to = $p[1]
                Invoke-Retrying { [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $to, $true) } "Unpacking $to" | Out-Null
            }
        }
    } finally {
        $archive.Dispose()
    }
}

# The first line of `<exe> --version`, or $null when it did not run within the time.
function Get-ProgramVersion([string]$Exe) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = '--version'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables['KRAKEN_NO_UPDATE_CHECK'] = '1'
    $proc = [System.Diagnostics.Process]::Start($psi)
    $out = $proc.StandardOutput.ReadToEndAsync()
    # The first start of a new program can wait for an antivirus scan.
    if (-not $proc.WaitForExit(120000)) {
        try { $proc.Kill() } catch { }
        return $null
    }
    if ($proc.ExitCode -ne 0) { return $null }
    return ($out.Result -split "`r?`n")[0].Trim()
}

# Stops KRAKEN programs that run from $Prefix: the daemon politely first, then the rest.
function Stop-Kraken([string]$Prefix, [bool]$Ask) {
    $cli = Join-Path $Prefix 'bin\kraken.exe'
    if (Test-Path -LiteralPath $cli -PathType Leaf) {
        try {
            $p = Start-Process -FilePath $cli -ArgumentList 'daemon', 'stop' -WindowStyle Hidden -PassThru
            if (-not $p.WaitForExit(30000)) { try { $p.Kill() } catch { } }
        } catch { }
    }
    $running = @(Get-Process -Name $KrakenPrograms -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and (Test-Under $_.Path $Prefix) })
    if ($running.Count -eq 0) { return }
    $names = ($running | ForEach-Object { "$($_.ProcessName) ($($_.Id))" }) -join ', '
    if ($Ask) {
        $answer = Read-Host "KRAKEN is running ($names). Stop it to continue? [y/N]"
        if ($answer -notmatch '^[yY]') { throw 'KRAKEN is still running; close it and run the script again.' }
    } else {
        Write-Note "Stopping KRAKEN programs that are running: $names"
    }
    $running | ForEach-Object { try { $_.Kill() } catch { } }
    $running | ForEach-Object { try { $_.WaitForExit(10000) | Out-Null } catch { } }
}

# --- Path and Start Menu -----------------------------------------------------------------------

function Send-EnvironmentChanged {
    if (-not ('KrakenInstall.Env' -as [type])) {
        Add-Type -Namespace KrakenInstall -Name Env -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    # HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG: running programs reread the Path.
    [KrakenInstall.Env]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result) | Out-Null
}

# Reads the user's Path as stored (unexpanded) with its registry type.
function Get-UserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    if (-not $key) { return @{ Value = ''; Kind = [Microsoft.Win32.RegistryValueKind]::ExpandString } }
    try {
        if ($key.GetValueNames() -notcontains 'Path') {
            return @{ Value = ''; Kind = [Microsoft.Win32.RegistryValueKind]::ExpandString }
        }
        return @{
            Value = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Kind  = $key.GetValueKind('Path')
        }
    } finally {
        $key.Close()
    }
}

function Set-UserPath([string]$Value, $Kind) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        if ($Value) { $key.SetValue('Path', $Value, $Kind) } else { $key.DeleteValue('Path', $false) }
    } finally {
        $key.Close()
    }
    Send-EnvironmentChanged
}

# Adds $Dir at the end of the user's Path unless it is there; $true when it was added.
function Add-UserPath([string]$Dir) {
    $cur = Get-UserPath
    $entries = @($cur.Value -split ';' | Where-Object { $_ })
    foreach ($e in $entries) { if (Test-SamePath $e $Dir) { return $false } }
    Set-UserPath (($entries + $Dir) -join ';') $cur.Kind
    return $true
}

# Removes every entry equal to $Dir from the user's Path, leaving the others and the type alone.
function Remove-UserPath([string]$Dir) {
    $cur = Get-UserPath
    $entries = @($cur.Value -split ';' | Where-Object { $_ })
    $kept = @($entries | Where-Object { -not (Test-SamePath $_ $Dir) })
    if ($kept.Count -eq $entries.Count) { return $false }
    Set-UserPath ($kept -join ';') $cur.Kind
    return $true
}

function Update-SessionPath([string]$Dir, [bool]$Add) {
    $entries = @($env:Path -split ';' | Where-Object { $_ -and -not (Test-SamePath $_ $Dir) })
    if ($Add) { $entries += $Dir }
    $env:Path = $entries -join ';'
}

# The Start Menu folder `kraken setup --launchers` also uses (Programs\KRAKEN). The known folder
# follows redirection, so it is never built from %USERPROFILE%.
function Get-StartMenuDir {
    $programs = [Environment]::GetFolderPath('Programs')
    if (-not $programs) { return $null }
    return (Join-Path $programs 'KRAKEN')
}

function New-Shortcut([string]$Link, [string]$Target, [string]$WorkDir) {
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Link)) | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    try {
        $s = $shell.CreateShortcut($Link)
        $s.TargetPath = $Target
        $s.WorkingDirectory = $WorkDir
        $s.IconLocation = "$Target,0"
        $s.Description = 'KRAKEN reverse engineering workbench (Installed by KRAKEN)'
        $s.Save()
    } finally {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
    }
}

# --- install -----------------------------------------------------------------------------------

function Test-Interactive {
    # A saved script run in a console window can ask; a piped one (`irm | iex`) just says.
    return [bool]$KrakenScriptPath -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
}

function Assert-Platform {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This script installs KRAKEN on Windows. On Linux and macOS use scripts/install.sh.'
    }
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { }
        'ARM64' {
            if (-not $Force) {
                throw 'KRAKEN ships for x86-64 Windows only. Windows on ARM can run it under emulation: add -Force to install it anyway.'
            }
        }
        default { throw "KRAKEN ships for 64-bit (x86-64) Windows only; this computer reports $arch." }
    }
}

# Drops versions the updater kept that do not lead back from the version being installed, so
# `kraken update --rollback` and the updater's idea of what is installed stay true.
function Clear-StaleGenerations([string]$Ver) {
    $previous = Join-Path (Get-KrakenDataDir) 'previous'
    if (-not (Test-Path -LiteralPath $previous -PathType Container)) { return }
    foreach ($g in Get-ChildItem -LiteralPath $previous -Directory -ErrorAction SilentlyContinue) {
        $manifest = Join-Path $g.FullName 'manifest.json'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { continue }
        try { $m = [System.IO.File]::ReadAllText($manifest) | ConvertFrom-Json } catch { continue }
        $installed = Get-Prop $m 'installed'
        if ($installed -and $installed -ne $Ver) {
            Remove-Folder $g.FullName | Out-Null
        }
    }
}

function Install-Kraken {
    Assert-Platform
    Initialize-Network
    $prefix = Get-InstallDir
    $tag = $Version
    if (-not $tag) { $tag = $env:KRAKEN_VERSION }
    if ($tag -and -not $tag.StartsWith('v')) { $tag = "v$tag" }
    if (-not $tag) {
        Write-Step 'Looking up the newest KRAKEN release'
        $tag = Get-LatestVersion
    }
    if ($tag -cnotmatch '^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') {
        throw "'$tag' is not a KRAKEN release tag (vX.Y.Z)."
    }
    $ver = $tag.Substring(1)
    $top = "kraken-$ver-$KrakenTarget"
    $zipName = "$top.zip"
    $base = "https://github.com/$KrakenRepo/releases/download/$tag"

    $old = Read-Receipt $prefix
    if ((Test-Path -LiteralPath $prefix) -and -not $old -and -not $Force) {
        $items = @(Get-ChildItem -LiteralPath $prefix -Force -ErrorAction SilentlyContinue)
        if ($items.Count -gt 0) {
            throw "$prefix exists and was not installed by this script. Pick another folder with -InstallDir, or add -Force to replace it."
        }
    }

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("kraken-install-" + [guid]::NewGuid().ToString('N'))
    $staging = "$prefix.new"
    [System.IO.Directory]::CreateDirectory($work) | Out-Null
    try {
        Write-Step "Downloading KRAKEN $ver"
        $sums = Join-Path $work 'SHA256SUMS'
        $sig = Join-Path $work 'SHA256SUMS.minisig'
        $zip = Join-Path $work $zipName
        Invoke-Download "$base/SHA256SUMS" $sums
        try {
            Invoke-Download "$base/SHA256SUMS.minisig" $sig
        } catch {
            throw "Release $tag has no signature (SHA256SUMS.minisig). Without a valid signature nothing is installed."
        }

        Write-Step 'Checking the release signature'
        Test-ReleaseSignature $sums $sig $ver
        $want = Get-SumFor $sums $zipName
        if (-not $want) { throw "$zipName is not in the signed SHA256SUMS; this release has no Windows build." }

        Invoke-Download "$base/$zipName" $zip
        $got = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $want) {
            throw "$zipName does not match the signed SHA-256 (expected $want, got $got). Nothing was installed."
        }
        Write-Note "Signature and SHA-256 are good ($want)."

        Write-Step "Unpacking into $prefix"
        $parent = [System.IO.Path]::GetDirectoryName($prefix)
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
        foreach ($leftover in Get-ChildItem -LiteralPath $parent -Directory -ErrorAction SilentlyContinue) {
            $n = $leftover.Name
            $leaf = [System.IO.Path]::GetFileName($prefix)
            if ($n -eq "$leaf.new" -or $n.StartsWith("$leaf.old-")) { Remove-Folder $leftover.FullName | Out-Null }
        }
        if (Test-Path -LiteralPath $staging) { throw "Cannot clear $staging; remove it and run the script again." }
        Expand-Release $zip $staging $top
        $newExe = Join-Path $staging 'bin\kraken.exe'
        if (-not (Test-Path -LiteralPath $newExe -PathType Leaf)) {
            throw 'The release zip does not hold bin\kraken.exe; nothing was installed.'
        }
        $reported = Get-ProgramVersion $newExe
        if ($reported -ne "kraken $ver" -and -not ("$reported".StartsWith("kraken $ver "))) {
            throw "The new kraken.exe reports '$reported', not 'kraken $ver'; nothing was installed."
        }

        # Swap: the old folder aside, the new one in, the old one deleted.
        $aside = $null
        if (Test-Path -LiteralPath $prefix) {
            Stop-Kraken $prefix ((Test-Interactive) -and -not $Force)
            $n = 1
            while (Test-Path -LiteralPath "$prefix.old-$n") { $n++ }
            $aside = "$prefix.old-$n"
            try {
                Move-Retrying $prefix $aside
            } catch {
                throw "$($_.Exception.Message). Close every KRAKEN window and terminal using it, then run the script again."
            }
        }
        try {
            Move-Retrying $staging $prefix
        } catch {
            if ($aside) { Move-Retrying $aside $prefix }
            throw
        }

        $bin = Join-Path $prefix 'bin'
        $pathAdded = [bool](Get-Prop $old 'path_added')
        if (-not $NoPath) {
            if (Add-UserPath $bin) { $pathAdded = $true }
            Update-SessionPath $bin $true
        }
        $shortcut = ''
        if (-not $NoShortcut) {
            $menu = Get-StartMenuDir
            $gui = Join-Path $bin 'kraken-gui.exe'
            if ($menu -and (Test-Path -LiteralPath $gui -PathType Leaf)) {
                $shortcut = Join-Path $menu 'KRAKEN.lnk'
                try {
                    New-Shortcut $shortcut $gui ([Environment]::GetFolderPath('UserProfile'))
                } catch {
                    Write-Note "No Start Menu shortcut: $($_.Exception.Message)"
                    $shortcut = ''
                }
            }
        } elseif (Get-Prop $old 'shortcut') {
            $shortcut = [string](Get-Prop $old 'shortcut')
        }
        Write-Receipt $prefix $ver $pathAdded $shortcut
        Clear-StaleGenerations $ver

        if ($aside -and -not (Remove-Folder $aside)) {
            Write-Note "The old version is still in use, so $aside stays; the next install removes it."
        }

        $other = Get-Command kraken.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        Write-Host ''
        Write-Host "KRAKEN $ver is installed in $prefix"
        if ($other -and -not (Test-SamePath ([System.IO.Path]::GetDirectoryName($other.Source)) $bin)) {
            Write-Host "Note: another kraken.exe comes first on your Path ($($other.Source)); remove it or put $bin before it."
        }
        Write-Host ''
        Write-Host 'Next steps:'
        if ($pathAdded) { Write-Host '  - Open a new terminal so the kraken command is found.' }
        Write-Host '  - kraken --version             check the install'
        Write-Host '  - kraken-gui                   the app (also in the Start Menu)'
        if (Test-Path -LiteralPath (Join-Path $bin 'kraken-native-worker.exe') -PathType Leaf) {
            Write-Host '  - The native engine is included and needs no Java.'
            Write-Host '  - kraken setup                 only for the Ghidra engine: downloads Ghidra and a JDK'
        } else {
            Write-Host '  - kraken setup                 downloads Ghidra and a JDK for the Ghidra engine'
            Write-Host '    Its sandbox exists on Linux only, so on Windows analysis needs KRAKEN_ALLOW_UNCONFINED=1;'
            Write-Host '    Ghidra then runs as you, unconfined: open only files you trust.'
        }
        Write-Host '  - claude mcp add kraken -- kraken mcp    connect an AI agent'
        Write-Host '  - kraken update                updates KRAKEN; kraken update --rollback goes back'
        Write-Host '  - Remove it again with this script and -Uninstall.'
    } finally {
        Remove-Folder $work | Out-Null
        if (Test-Path -LiteralPath $staging) { Remove-Folder $staging | Out-Null }
    }
}

function Uninstall-Kraken {
    Assert-Platform
    $prefix = Get-InstallDir
    $r = Read-Receipt $prefix
    if (-not $r) {
        throw "$prefix holds no KRAKEN install made by this script (share\kraken\install.json). Nothing was removed."
    }
    Write-Step "Removing KRAKEN $(Get-Prop $r 'version') from $prefix"
    Stop-Kraken $prefix ((Test-Interactive) -and -not $Force)
    # The folder goes aside first: if something still holds it, nothing else has changed yet.
    $n = 1
    while (Test-Path -LiteralPath "$prefix.old-$n") { $n++ }
    $aside = "$prefix.old-$n"
    try {
        Move-Retrying $prefix $aside
    } catch {
        throw "$($_.Exception.Message). Close every KRAKEN window and terminal using it, then run the script again."
    }
    $bin = Join-Path $prefix 'bin'
    if (Get-Prop $r 'path_added') {
        if (Remove-UserPath $bin) { Write-Note "Removed $bin from your Path." }
    }
    Update-SessionPath $bin $false
    $link = [string](Get-Prop $r 'shortcut')
    if ($link) {
        $menu = Get-StartMenuDir
        if ($link.EndsWith('.lnk', [System.StringComparison]::OrdinalIgnoreCase) -and $menu -and (Test-Under $link $menu) -and (Test-Path -LiteralPath $link -PathType Leaf)) {
            Remove-Item -LiteralPath $link -Force
            Write-Note 'Removed the Start Menu shortcut.'
            if (@(Get-ChildItem -LiteralPath $menu -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item -LiteralPath $menu -Force -ErrorAction SilentlyContinue
            }
        }
    }
    if (Remove-Folder $aside) {
        Write-Note "Removed $prefix."
    } else {
        Write-Note "Something still uses $aside; delete it after closing it (or restarting)."
    }
    $data = Get-KrakenDataDir
    if ($Purge) {
        # `kraken setup --launchers` keeps its commands in <data>\bin (the same folder as
        # %LOCALAPPDATA%\KRAKEN\bin, since Windows paths ignore case) and puts it on the Path.
        if (Remove-UserPath (Join-Path $data 'bin')) { Write-Note "Removed $(Join-Path $data 'bin') from your Path." }
        foreach ($dir in @($data, (Get-KrakenConfigDir))) {
            if ($dir -and (Test-Path -LiteralPath $dir)) {
                if (Remove-Folder $dir) { Write-Note "Removed $dir." } else { Write-Note "Could not remove all of $dir." }
            }
        }
    } else {
        Write-Host ''
        Write-Host "KRAKEN is removed. Your projects stay where you created them; downloaded engines, caches and"
        Write-Host "kept versions stay in $data (run with -Uninstall -Purge to remove them too)."
    }
}

function Invoke-KrakenInstaller {
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    try {
        if ($Uninstall) { Uninstall-Kraken } else { Install-Kraken }
        return $true
    } catch {
        Write-Host ''
        Write-Host "KRAKEN install: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception -isnot [System.Management.Automation.RuntimeException]) {
            Write-Host $_.ScriptStackTrace
        }
        return $false
    }
}

# Everything runs inside functions, so a piped run (`irm | iex`) changes nothing in the caller's
# session and a failure never closes its window.
$krakenOk = Invoke-KrakenInstaller
if (-not $krakenOk -and $KrakenScriptPath) { exit 1 }
