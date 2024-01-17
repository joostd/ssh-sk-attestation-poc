#!/usr/bin/env php
<?php

include("common.php");

# input must be binary TLV data
$s = file_get_contents('php://stdin');

while($s) {
	[$t,$l,$v] = tlv($s);
	echo bin2hex($t).",";
	echo bin2hex($l).",";
	echo bin2hex($v)."\n";
}

assert($s==="");
