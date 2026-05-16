<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Security\Helper\Voter;

/**
 * Intentionally does NOT implement VoterInterface — used to exercise the
 * SecureContainer guard against misconfigured voter classes.
 */
final class NotAVoter {}
