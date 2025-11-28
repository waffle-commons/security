Waffle Commons -[![PHP Version Require](http://poser.pugx.org/waffle-commons/security/require/php)](https://packagist.org/packages/waffle-commons/security)
[![PHP CI](https://github.com/waffle-commons/security/actions/workflows/main.yml/badge.svg)](https://github.com/waffle-commons/security/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/waffle-commons/security/graph/badge.svg?token=d74ac62a-7872-4035-8b8b-bcc3af1991e0)](https://codecov.io/gh/waffle-commons/security)
[![Latest Stable Version](http://poser.pugx.org/waffle-commons/security/v)](https://packagist.org/packages/waffle-commons/security)
[![Latest Unstable Version](http://poser.pugx.org/waffle-commons/security/v/unstable)](https://packagist.org/packages/waffle-commons/security)
[![Total Downloads](https://img.shields.io/packagist/dt/waffle-commons/security.svg)](https://packagist.org/packages/waffle-commons/security)
[![Packagist License](https://img.shields.io/packagist/l/waffle-commons/security)](https://github.com/waffle-commons/security/blob/main/LICENSE.md)

Waffle Security Component
=========================

A flexible security layer for Waffle applications, providing rule-based access control and security context management.

## 📦 Installation

```bash
composer require waffle-commons/security
```

## 🚀 Usage

### Basic Usage

```php
use Waffle\Commons\Security\Security;
use Waffle\Commons\Config\Config;

// Initialize Security with Config
$config = new Config('/path/to/config', 'prod');
$security = new Security($config);

// Analyze an object against security rules
$security->analyze($myObject);
```

### Security Rules

The security component analyzes objects to ensure they meet specific criteria (e.g., immutability, final classes) based on the configured security level.

Testing
-------

To run the tests, use the following command:

```bash
composer tests
```

Contributing
------------

Contributions are welcome! Please refer to [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

License
-------

This project is licensed under the MIT License. See the [LICENSE.md](./LICENSE.md) file for details.=========
