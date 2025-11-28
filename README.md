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

$security = new Security();

// Check if the current context allows an action
if ($security->isGranted('ROLE_ADMIN')) {
    // ...
}
```

### Security Rules

You can define security rules to restrict access to specific parts of your application.

```php
use Waffle\Commons\Security\Rule\PathRule;

// Deny access to /admin unless user has ROLE_ADMIN
$rule = new PathRule('/admin', ['ROLE_ADMIN']);
```=========
