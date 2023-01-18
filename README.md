# crutch/crypt-openssl

Crypt interface

# Install

```bash
composer require crutch/crypt-openssl
```

# Usage

```php
<?php

$crypt = new Crutch\OpenSslCrypt\OpenSslCrypt('secret', 16);
$value = 'test'
$encrypted = $crypt->encrypt($value);
$decrypted = $crypt->decrypt($encrypted);

var_dump($value === $decrypted);
```
