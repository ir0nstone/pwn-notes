# PHP Master

Once we visit the URL, we are shown some code:

```php
<?php

include('flag.php');

$p1 = $_GET['param1'];
$p2 = $_GET['param2'];

if(!isset($p1) || !isset($p2)) {
    highlight_file(__FILE__);
    die();
}

if(strpos($p1, 'e') === false && strpos($p2, 'e') === false  && strlen($p1) === strlen($p2) && $p1 !== $p2 && $p1[0] != '0' && $p1 == $p2) {
    die($flag);
}

?>
```

Clearly this is some type of [Type Juggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling) exploit, but I'm not that familiar with it except for `0e` md5 hashes and stuff. However, there are some restrictions here:

* There can be no `e` character in either parameter
* The two parameters must be the same length
* They can't strictly equal each other \(`!==`\) but they must loosely equal each other \(`==`\)

PHP comparision is a known piece of junk, so we can find some weaknesses using [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling).

Once set of possible parameters is `01` and  `1`, as they are both two characters long and - according to PHP's loose comparison - equal each other \(thanks to [**nrabulinski** ](https://github.com/nrabulinski)for this solution after the CTF\). It appears that objetcs are automatically **converted to numbers** for loose comparisions, as loose only compares _values_ while strict _also compares types_. Therefore the example above would both equal `1` under loose comparison.

Another, more interesting set is `200` and `2E3` \(thanks to [03sunf](https://gist.github.com/03sunf/ada95212b624d9354b9f9cc46b14f387)\). Note that `2E3` is an **exponential**, equivalent to `2 * 10^2`. Once both are converted to integers, they pass the check.

