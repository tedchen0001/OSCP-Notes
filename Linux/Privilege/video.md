iraw2png.pl

```
#!/usr/bin/perl -w

 

$w = shift || 240;
$h = shift || 320;
$pixels = $w * $h;

 

open OUT, "|pnmtopng" or die "Can't pipe pnmtopng: $!\n";

 

printf OUT "P6%d %d\n255\n", $w, $h;

 

while ((read STDIN, $raw, 2) and $pixels--) {
$short = unpack('S', $raw);
print OUT pack("C3",
($short & 0xf800) >> 8,
($short & 0x7e0) >> 3,
($short & 0x1f) << 3);
}

 

close OUT;
```

Target server

```
id

ls -lah /dev/fb0

cat /dev/fb0 > /tmp/temp.raw #upload to Host

cat /sys/class/graphics/fb0/virtual_size #1176,885
```

Host server

```
chmod +x iraw2png.pl

./iraw2png.pl 1176 885 < temp.raw > screen.png
```
