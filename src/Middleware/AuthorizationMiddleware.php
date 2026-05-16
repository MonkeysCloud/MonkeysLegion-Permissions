<?php
declare(strict_types=1);

namespace MonkeysLegion\Permissions\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use MonkeysLegion\Permissions\Contracts\AuthorizerInterface;
use MonkeysLegion\Permissions\Attributes\RequiresPermission;
use MonkeysLegion\Permissions\Attributes\RequiresRole;
use MonkeysLegion\Permissions\Attributes\Authorize;
use MonkeysLegion\Permissions\Attributes\Gate;
use MonkeysLegion\Auth\Contract\AuthenticatableInterface;
use MonkeysLegion\Permissions\Exceptions\AuthorizationException;

/**
 * MonkeysLegion Framework — Permissions Package
 *
 * Intercepts HTTP requests and evaluates authorization attributes attached to the route handler.
 *
 * @copyright 2026 MonkeysCloud Team
 * @license   MIT
 */
final class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly AuthorizerInterface $authorizer,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Assume the Router places the resolved handler's ReflectionMethod or attributes into the request.
        // For standard MonkeysLegion v2, it's typically under '_route_attributes'.
        /** @var array<object> $attributes */
        $attributes = $request->getAttribute('_route_attributes', []);

        if (empty($attributes)) {
            return $handler->handle($request);
        }

        /** @var AuthenticatableInterface|null $identity */
        $identity = $request->getAttribute(AuthenticatableInterface::class);

        // If no identity is authenticated but auth is required, let the AuthenticationMiddleware handle it.
        // If an attribute exists here, we need an identity.
        $needsAuth = false;
        foreach ($attributes as $attr) {
            if ($attr instanceof RequiresPermission || $attr instanceof RequiresRole || $attr instanceof Authorize || $attr instanceof Gate) {
                $needsAuth = true;
                break;
            }
        }

        if ($needsAuth && $identity === null) {
            throw new AuthorizationException("Unauthenticated.");
        }

        if ($identity !== null) {
            foreach ($attributes as $attr) {
                if ($attr instanceof RequiresPermission) {
                    $this->handleRequiresPermission($identity, $attr);
                } elseif ($attr instanceof RequiresRole) {
                    $this->handleRequiresRole($identity, $attr);
                } elseif ($attr instanceof Gate) {
                    $this->authorizer->authorize($identity, $attr->name);
                } elseif ($attr instanceof Authorize) {
                    $resourceId = $attr->paramName ? $request->getAttribute($attr->paramName) : null;
                    // Note: If the resource is fully bound via Route Model Binding, the Router 
                    // should provide the entity instance under $attr->paramName.
                    $this->authorizer->authorize($identity, $attr->ability, $resourceId);
                }
            }
        }

        return $handler->handle($request);
    }

    private function handleRequiresPermission(AuthenticatableInterface $identity, RequiresPermission $attr): void
    {
        if ($attr->permission !== null) {
            $this->authorizer->authorize($identity, $attr->permission, null, $attr->tenant);
        }

        foreach ($attr->allOf as $perm) {
            $this->authorizer->authorize($identity, $perm, null, $attr->tenant);
        }

        if (!empty($attr->anyOf)) {
            $passed = false;
            foreach ($attr->anyOf as $perm) {
                if ($this->authorizer->hasPermission($identity, $perm, $attr->tenant)) {
                    $passed = true;
                    break;
                }
            }
            if (!$passed) {
                throw new AuthorizationException("None of the required permissions were met.");
            }
        }
    }

    private function handleRequiresRole(AuthenticatableInterface $identity, RequiresRole $attr): void
    {
        if ($attr->role !== null) {
            if (!$this->authorizer->hasRole($identity, $attr->role, $attr->tenant)) {
                throw new AuthorizationException("Requires role [{$attr->role}].");
            }
        }

        foreach ($attr->allOf as $role) {
            if (!$this->authorizer->hasRole($identity, $role, $attr->tenant)) {
                throw new AuthorizationException("Requires role [{$role}].");
            }
        }

        if (!empty($attr->anyOf)) {
            $passed = false;
            foreach ($attr->anyOf as $role) {
                if ($this->authorizer->hasRole($identity, $role, $attr->tenant)) {
                    $passed = true;
                    break;
                }
            }
            if (!$passed) {
                throw new AuthorizationException("None of the required roles were met.");
            }
        }
    }
}
