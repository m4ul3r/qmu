# Boot command lines: `--append`, `--cmdline`, profiles, and the unknown-parameter lint

Companion to `skill://qmu`.

## Precedence

- `--cmdline` REPLACES the whole resolved command line; every built-in profile
  carries `root=/dev/sda`, and a replacement that omits it boots into an
  emergency shell with no obvious cause (qmu warns on stderr when a `--cmdline`
  without `root=` is paired with an attached rootfs). `--append` ADDs parameters
  onto whichever line won the resolution below.
- A `[boot] cmdline` in `qmu.toml` is a full override and normally beats the
  default profile (the profile then contributes nothing, so `--append` lands on
  the config line).
- An explicit CLI `--profile` beats that config cmdline — otherwise `--profile
  exploit-test` would be a silent no-op in any project whose config sets a
  cmdline — and says so on stderr, listing every dropped param and calling out
  the ones that silently invalidate work:

```
[qmu] --profile exploit-test overrides the [boot] cmdline in qmu.toml for this launch.
[qmu]   dropped: nokaslr rw slub_debug=- init=/init.sh
[qmu]   note: 'nokaslr' is gone — every kernel address changes; hardcoded offsets will be wrong
[qmu]   note: 'init=/init.sh' is gone — the guest runs its default init, not your harness script
[qmu]   re-add any you still need with --append.
```

  Re-add them with `--append` in the same launch. `nokaslr` is the one to
  watch: a final-validation run under `--profile exploit-test` is exactly when
  you least want KASLR quietly back on.
- CLI `--cmdline` wins over both. When a full override applies, `qmu status`
  text marks the profile `(NOT applied — cmdline was overridden)` and JSON
  carries the bare `profile` name with `profile_applied: false`.

## The unknown-parameter lint

`launch` (once SSH is up) and `wait` report any boot
parameter the kernel did not claim — `unknown_kernel_params` in JSON, a stderr
warning in text. `status` does **not** (it never reads the guest's parameter
line); re-check with a fresh `wait --timeout 1` if you need the list later.
With `--no-wait-ssh` or `--harness` the `launch` key is still emitted but empty
(`[]`), which is "not checked", not "none unknown".

This catches the silent class of bug where a cmdline parameter looks right and
does nothing — `panic_on_oops=1` is a sysctl, not a boot parameter, so a
profile built on it never panics and a kernel-corrupting exploit reads as a
clean run. The boot form is `oops=panic`.

Three deliberate exclusions keep the warning worth reading:

- **Init-consumed** params (`root=`, `init=`, `console=`) always appear in the
  kernel's list and are never actionable.
- **Pre-parse** params are honored *before* the kernel's parameter table
  exists, so the kernel reports them as unknown while acting on them. **This is
  arch-specific and qmu gates it on the VM's arch.** On x86, `nokaslr` is read
  by the decompressor with no `__setup` entry to claim it — there it works, and
  you should not remove it on the strength of that kernel line; the same goes
  for `no5lvl`, `acpi*`, `earlyprintk`, `forcepae`, `edd`, and `mem_encrypt`.
  On **arm32 the opposite is true**: `arch/arm/` has no KASLR at all, so
  `nokaslr` there really does nothing and qmu reports it. arm64 never lists it
  (a do-nothing `early_param` claims it). An instance with no recorded arch
  suppresses only `quiet`/`debug`, so an unknown arch never hides a real dud.
- **Profile-supplied** params are reported on a separate, quieter `[qmu] Note:`
  line. They come from qmu's own profile rather than from anything you typed,
  and are usually unfixable by design (`apparmor=0` is unclaimed precisely
  because AppArmor is not compiled in). Only params *you* supplied get the loud
  warning.

JSON keeps the same split: `unknown_kernel_params_by_source.operator` is the
key to gate a script on — `unknown_kernel_params` stays as the flat list for
back-compat, but it includes the perpetual profile noise.

**Dotted params are a blind spot.** The kernel routes `foo.bar=x` to the
module-param path, so a dotted param never appears in that unknown-parameter
line at all — `kasan.faul=panic` is silently ignored at boot and invisible
afterwards. `launch` spell-checks dotted params against the names qmu knows and
warns on a near-miss; unrelated dotted params are left alone.

**`earlyprintk=serial` on ARM** is reported as unknown because arm64 does not
implement it; drop it from ARM cmdlines (the x86 profiles carry it because x86
does).
