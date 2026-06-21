<?php

namespace LdapRecord\Models\Concerns;

use Closure;
use LdapRecord\ConnectionException;
use LdapRecord\LdapRecordException;
use LdapRecord\Models\Attributes\Password;
use LdapRecord\Models\Model;

/** @mixin Model */
trait HasPassword
{
    /**
     * A password change deferred until the model is saved.
     */
    protected ?Closure $pendingPasswordChange = null;

    /**
     * Set the password on the user.
     *
     * @throws ConnectionException
     */
    public function setPasswordAttribute(array|string $password): void
    {
        $this->assertSecureConnection();

        // Here we will attempt to determine the password hash method in use
        // by parsing the users hashed password (if it as available). If a
        // method is determined, we will override the default here.
        if (! ($method = $this->determinePasswordHashMethod())) {
            $method = $this->getPasswordHashMethod();
        }

        // If the password given is an array, we can assume we
        // are changing the password for the current user.
        if (is_array($password)) {
            [$oldPassword, $newPassword] = $password;

            // Argon2 hashes embed a random salt, so the currently stored hash
            // cannot be reproduced to emit a REMOVE/ADD batch modification.
            // Instead we defer a self-service RFC 3062 Password Modify
            // extended operation until the model is saved.
            if ($this->passwordChangeRequiresExop($method)) {
                $this->pendingPasswordChange = fn () => $this->getConnection()->changePassword(
                    $this->getDn(), $oldPassword, $newPassword
                );

                return;
            }

            $this->setChangedPassword(
                $this->getHashedPassword($method, $oldPassword, $this->getPasswordSalt($method)),
                $this->getHashedPassword($method, $newPassword),
                $this->getPasswordAttributeName()
            );
        }
        // Otherwise, we will assume the password is being
        // reset, overwriting the one currently in place.
        else {
            $this->setPassword(
                $this->getHashedPassword($method, $password),
                $this->getPasswordAttributeName()
            );
        }
    }

    /**
     * Alias for setting the password on the user.
     *
     * @throws ConnectionException
     */
    public function setUnicodepwdAttribute(array|string $password): void
    {
        $this->setPasswordAttribute($password);
    }

    /**
     * An accessor for retrieving the user's hashed password value.
     */
    public function getPasswordAttribute(): ?string
    {
        return $this->getAttribute($this->getPasswordAttributeName())[0] ?? null;
    }

    /**
     * Get the name of the attribute that contains the user's password.
     */
    public function getPasswordAttributeName(): string
    {
        if (property_exists($this, 'passwordAttribute')) {
            return $this->passwordAttribute;
        }

        if (method_exists($this, 'passwordAttribute')) {
            return $this->passwordAttribute();
        }

        return 'unicodepwd';
    }

    /**
     * Get the name of the method to use for hashing the user's password.
     */
    public function getPasswordHashMethod(): string
    {
        if (property_exists($this, 'passwordHashMethod')) {
            return $this->passwordHashMethod;
        }

        if (method_exists($this, 'passwordHashMethod')) {
            return $this->passwordHashMethod();
        }

        return 'encode';
    }

    /**
     * Set the changed password.
     */
    protected function setChangedPassword(string $oldPassword, string $newPassword, string $attribute): void
    {
        // Create batch modification for removing the old password.
        $this->addModification(
            $this->newBatchModification(
                $attribute,
                LDAP_MODIFY_BATCH_REMOVE,
                [$oldPassword]
            )
        );

        // Create batch modification for adding the new password.
        $this->addModification(
            $this->newBatchModification(
                $attribute,
                LDAP_MODIFY_BATCH_ADD,
                [$newPassword]
            )
        );
    }

    /**
     * Determine if changing a password hashed with the given method requires
     * an extended operation rather than a batch modification.
     */
    protected function passwordChangeRequiresExop(string $method): bool
    {
        return match (strtolower($method)) {
            'argon2i', 'argon2id' => true,
            default => false,
        };
    }

    /**
     * Determine if the model has a password change deferred until save.
     */
    public function hasPendingPasswordChange(): bool
    {
        return ! is_null($this->pendingPasswordChange);
    }

    /**
     * Flush any password change deferred until save.
     *
     * @throws LdapRecordException
     */
    public function flushPendingPasswordChange(): void
    {
        if (! $change = $this->pendingPasswordChange) {
            return;
        }

        // Clear the pending change before executing it so a failed operation
        // cannot be re-applied if the save is retried.
        $this->pendingPasswordChange = null;

        $change();
    }

    /**
     * Perform any operations deferred until the model is saved.
     *
     * @throws LdapRecordException
     */
    protected function performDeferredOperations(): void
    {
        $this->flushPendingPasswordChange();
    }

    /**
     * Set the password on the model.
     */
    protected function setPassword(string $password, string $attribute): void
    {
        if (! $this->exists) {
            $this->setRawAttribute($attribute, $password);

            return;
        }

        $this->addModification(
            $this->newBatchModification(
                $attribute,
                LDAP_MODIFY_BATCH_REPLACE,
                [$password]
            )
        );
    }

    /**
     * Encode / hash the given password.
     *
     * @throws LdapRecordException
     */
    protected function getHashedPassword(string $method, string $password, ?string $salt = null): string
    {
        if (! method_exists(Password::class, $method)) {
            throw new LdapRecordException("Password hashing method [{$method}] does not exist.");
        }

        if (Password::hashMethodRequiresSalt($method)) {
            return Password::{$method}($password, $salt);
        }

        return Password::{$method}($password);
    }

    /**
     * Validates that the current LDAP connection is secure.
     *
     * @throws ConnectionException
     */
    protected function assertSecureConnection(): void
    {
        $connection = $this->getConnection();

        $config = $connection->getConfiguration();

        if ($config->get('allow_insecure_password_changes') === true) {
            return;
        }

        if ($connection->isConnected()) {
            $secure = $connection->getLdapConnection()->canChangePasswords();
        } else {
            $secure = $config->get('use_tls') || $config->get('use_starttls');
        }

        if (! $secure) {
            throw new ConnectionException(
                'You must be connected to your LDAP server with TLS or StartTLS to perform this operation.'
            );
        }
    }

    /**
     * Attempt to retrieve the password's salt.
     */
    public function getPasswordSalt(string $method): ?string
    {
        if (! Password::hashMethodRequiresSalt($method)) {
            return null;
        }

        return Password::getSalt($this->password);
    }

    /**
     * Determine the password hash method to use from the users current password.
     */
    public function determinePasswordHashMethod(): ?string
    {
        if (! $password = $this->password) {
            return null;
        }

        if (! $method = Password::getHashMethod($password)) {
            return null;
        }

        if (! $hashAndAlgo = Password::getHashMethodAndAlgo($password)) {
            return $method;
        }

        [,$algo] = array_pad(array: $hashAndAlgo, length: 2, value: null);

        return match ((int) $algo) {
            Password::CRYPT_SALT_TYPE_MD5 => 'md5'.$method,
            Password::CRYPT_SALT_TYPE_SHA256 => 'sha256'.$method,
            Password::CRYPT_SALT_TYPE_SHA512 => 'sha512'.$method,
            default => $method,
        };
    }
}
