# scanf Bypasses

Sometimes you want `scanf` to not read anything, but continue standard execution. By this I mean that it **takes** your input, but it doesn't store it in memory, leaving the stack or heap untouched.

This might be because you have a sequential or iterative OOB write, but there is a canary in the way. Alternatively, the location you are writing to is **uninitialized** but the data gets printed back and you want to leak pointers this way (e.g. [Control Room](https://app.hackthebox.com/challenges/Control%20Room) on Hack The Box).

So, here are a few inputs for different specifiers that help bypass this! Please do let me know of any more.

<table><thead><tr><th width="378">Scanf Specifier</th><th>Bypass</th></tr></thead><tbody><tr><td><code>%d</code>, <code>%ld</code></td><td>negative sign <code>-</code></td></tr><tr><td><code>%f</code>, <code>%lf</code></td><td>decimal point/full stop <code>.</code></td></tr><tr><td></td><td></td></tr></tbody></table>
