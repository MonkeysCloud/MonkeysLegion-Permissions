# MonkeysLegion Permissions v1

Enterprise RBAC, policy gates, composable rules, approval workflows, LDAP/SAML sync, and Apex AI fuzzy authorization for MonkeysLegion. Ground-up build for PHP 8.4 with property hooks, backed enums, and zero magic.

## Features

| Feature | Status |
|---|---|
| **Authorizer Pipeline** | Gate → PolicyResolver → RuleEngine → Decision |
| **Attribute-First Security** | `#[RequiresRole]`, `#[RequiresPermission]`, `#[Authorize]`, `#[Gate]` |
| **Policy System** | Model-to-policy mapping with `before()` / `after()` hooks |
| **Composable Rules** | Predicate engine with AND/OR/NOT/CUSTOM operators, priority-based execution |
| **Database Store** | Role, Permission, UserRole, UserPermission, StoredRule entities |
| **Approval Workflows** | PermissionRequest → review → approve/deny with expiry |
| **Cache Layer** | Transparent permission caching with TTL and tag-based invalidation |
| **LDAP/SAML Sync** | RoleSyncAdapterInterface with additive/replace/merge/intersect strategies |
| **Apex AI Integration** | LLM-backed fuzzy policy evaluation with confidence thresholds |
| **PSR-15 Middleware** | AuthorizationMiddleware — attribute-aware request authorization |
| **Event System** | 11 audit events for authorization, roles, permissions, and sync |
| **CLI Commands** | `permissions:install`, `permissions:entities` |
| **PHP 8.4 Native** | Property hooks, backed enums, asymmetric visibility |

## Requirements

- **PHP 8.4** or higher
- `monkeyscloud/monkeyslegion-di` (Container)
- `monkeyscloud/monkeyslegion-events` (Event dispatching)
- `psr/http-message` ^2.0
- `psr/http-server-middleware` ^1.0

## Installation

```bash
composer require monkeyscloud/monkeyslegion-permissions
```

### Quick Setup

```bash
# Full install: config + entities + migration
php ml permissions:install

# Or just copy entity stubs
php ml permissions:entities
php ml permissions:entities --force  # overwrite existing
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   HTTP Request                           │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│          AuthorizationMiddleware (PSR-15)                │
│  Reads: #[RequiresRole] #[RequiresPermission] #[Gate]   │
└───────────────────────┬─────────────────────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────┐
│                    Authorizer                            │
│  ┌──────┐  ┌────────────┐  ┌────────────┐  ┌────────┐  │
│  │ Gate │→ │PolicyResolve│→ │ RuleEngine │→ │Decision│  │
│  └──────┘  └────────────┘  └────────────┘  └────────┘  │
└─────────────────────────────────────────────────────────┘
                        ▼
┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐
│ Database │  │   Cache   │  │  Events  │  │  Apex AI  │
│  Store   │  │   Layer   │  │ Dispatch │  │  (opt.)   │
└──────────┘  └───────────┘  └──────────┘  └───────────┘
```

The package is organized into clear namespaces:

- `Apex/`: AI-powered fuzzy policy evaluation (`ApexPolicyAdapter`, `ApexGateRegistrar`)
- `Attributes/`: Controller/method attributes (`#[RequiresRole]`, `#[RequiresPermission]`, `#[Authorize]`, `#[Gate]`)
- `Cache/`: Transparent permission caching (`CacheLayer`)
- `Contracts/`: Core interfaces (`AuthorizerInterface`)
- `Entity/`: Database entities (Role, Permission, UserRole, UserPermission, StoredRule, PermissionRequest)
- `Event/`: 11 audit events for all authorization operations
- `Exceptions/`: `AuthorizationException`
- `Gate/`: Ability definitions and closures
- `Middleware/`: PSR-15 `AuthorizationMiddleware`
- `Policy/`: Model-to-policy mapping (`Policy`, `PolicyResolver`)
- `Provider/`: DI service provider (`PermissionsProvider`)
- `Rule/`: Composable predicate engine (`Rule`, `Predicate`, `RuleEngine`)
- `Store/`: Database persistence (`DatabaseStore`, `PermissionStoreInterface`)
- `Sync/`: LDAP/SAML role synchronization (`RoleSyncManager`, adapters)
- `Workflow/`: Approval request pipeline (`RequestManager`)

## Configuration

```bash
cp vendor/monkeyscloud/monkeyslegion-permissions/config/permissions.mlc config/permissions.mlc
```

```
permissions {
    # Super-admin role (has all permissions)
    super_admin_role = ${PERMISSIONS_SUPER_ADMIN:-super-admin}

    # Table names
    tables {
        roles            = ${PERMISSIONS_TABLE_ROLES:-perm_roles}
        permissions      = ${PERMISSIONS_TABLE_PERMISSIONS:-perm_permissions}
        user_roles       = ${PERMISSIONS_TABLE_USER_ROLES:-perm_user_roles}
        user_permissions = ${PERMISSIONS_TABLE_USER_PERMISSIONS:-perm_user_permissions}
        stored_rules     = ${PERMISSIONS_TABLE_STORED_RULES:-perm_stored_rules}
        requests         = ${PERMISSIONS_TABLE_REQUESTS:-perm_permission_requests}
    }

    # Permission caching
    cache {
        enabled = ${PERMISSIONS_CACHE_ENABLED:-true}
        ttl     = ${PERMISSIONS_CACHE_TTL:-3600}
        prefix  = ${PERMISSIONS_CACHE_PREFIX:-perm:}
    }

    # Apex AI integration (optional)
    apex {
        confidence_threshold = ${PERMISSIONS_APEX_THRESHOLD:-0.7}
        model = ${PERMISSIONS_APEX_MODEL:-}
    }
}
```

## Attribute-Based Authorization

```php
use MonkeysLegion\Permissions\Attributes\RequiresRole;
use MonkeysLegion\Permissions\Attributes\RequiresPermission;
use MonkeysLegion\Permissions\Attributes\Authorize;

#[RequiresRole('admin')]
class AdminController
{
    #[RequiresPermission('users.create')]
    public function createUser(): Response
    {
        // Only accessible to admins with users.create permission
    }

    #[Authorize('update-user', subject: 'user')]
    public function updateUser(int $id): Response
    {
        // Delegates to a policy: UserPolicy::update($currentUser, $user)
    }
}
```

## Gate (Ability Definitions)

```php
use MonkeysLegion\Permissions\Gate;

$gate = new Gate();

// Define abilities with closures
$gate->define('edit-post', fn($user, $post) => $user->id === $post->author_id);

// Check
$gate->allows($user, 'edit-post', $post);   // true/false
$gate->denies($user, 'edit-post', $post);   // true/false
$gate->authorize($user, 'edit-post', $post); // throws AuthorizationException
```

## Policy System

```php
use MonkeysLegion\Permissions\Policy\Policy;

class PostPolicy extends Policy
{
    public function update(object $user, object $post): bool
    {
        return $user->id === $post->author_id;
    }

    public function delete(object $user, object $post): bool
    {
        return $user->role === 'admin';
    }

    // Optional: runs before any check
    public function before(object $user, string $ability): ?bool
    {
        // Super-admins can do anything
        if ($user->role === 'super-admin') {
            return true;
        }
        return null; // fall through to specific check
    }
}
```

## Composable Rules

```php
use MonkeysLegion\Permissions\Rule\Rule;
use MonkeysLegion\Permissions\Rule\Predicate;
use MonkeysLegion\Permissions\Rule\PredicateType;
use MonkeysLegion\Permissions\Rule\RuleEngine;

// Build rules with predicates
$rule = new Rule(
    name: 'business-hours-only',
    key: 'business_hours',
    predicates: [
        new Predicate(PredicateType::Custom, fn() => date('H') >= 9 && date('H') < 17),
    ],
    priority: 10,
);

$engine = new RuleEngine();
$engine->addRule($rule);

$result = $engine->evaluate($context);
// RuleResult: allowed, denied, or abstained
```

## Approval Workflows

```php
use MonkeysLegion\Permissions\Workflow\RequestManager;

$manager = $container->get(RequestManager::class);

// User requests a permission
$request = $manager->request(
    userId: 'user-42',
    targetKey: 'reports.export',
    reason: 'Need to export Q4 reports for client presentation',
);

// Admin reviews
$manager->approve($request, reviewedBy: 'admin-1', note: 'Approved for Q4');
// or
$manager->deny($request, reviewedBy: 'admin-1', note: 'Use dashboard instead');
```

## LDAP/SAML Sync

```php
use MonkeysLegion\Permissions\Sync\RoleSyncManager;
use MonkeysLegion\Permissions\Sync\SyncStrategy;

$sync = $container->get(RoleSyncManager::class);

// Sync roles from external identity provider
$result = $sync->sync(
    userId: 'user-42',
    externalRoles: ['engineering', 'team-lead'],
    strategy: SyncStrategy::Merge,
);

// SyncResult: added, removed, unchanged counts
```

Strategies:
| Strategy | Behavior |
|---|---|
| `Additive` | Only add new roles, never remove |
| `Replace` | External roles replace all local roles |
| `Merge` | Union of external and local roles |
| `IntersectLocal` | Keep only roles that exist both externally and locally |

## Apex AI Fuzzy Authorization

```php
use MonkeysLegion\Permissions\Apex\ApexGateRegistrar;

$registrar = $container->get(ApexGateRegistrar::class);

// Register AI-powered policy
$registrar->register(
    gateName: 'content-appropriate',
    prompt: 'Is the following content appropriate for a professional workplace?',
    confidenceThreshold: 0.8,
);

// Now use it like any other gate
$authorizer->authorize($user, 'content-appropriate', ['content' => $postBody]);
```

## Database Entities

The package includes 8 entity stubs ready for database persistence:

| Entity | Purpose |
|---|---|
| `Role` | Roles with key, name, level, metadata |
| `Permission` | Permissions with key, name, group |
| `UserRole` | User ↔ Role assignments with expiry |
| `UserPermission` | Direct user ↔ permission grants with expiry |
| `StoredRule` | Persistent composable rules with predicates |
| `PermissionRequest` | Approval workflow requests |
| `RequestStatus` | Enum: pending, approved, denied, expired |
| `RequestType` | Enum: permission, role |

## Events

| Event | When Dispatched |
|---|---|
| `AuthorizationChecked` | Any authorization check completes |
| `AuthorizationDenied` | Authorization denied |
| `PermissionGranted` | Permission assigned to user |
| `PermissionRevoked` | Permission removed from user |
| `PermissionRequested` | User requests a permission |
| `RequestApproved` | Request approved by reviewer |
| `RequestDenied` | Request denied by reviewer |
| `RoleAssigned` | Role assigned to user |
| `RoleRevoked` | Role removed from user |
| `RolesSynced` | External role sync completed |
| `ApexPolicyEvaluated` | AI policy evaluation completed |
| `PolicyEvaluated` | Standard policy evaluation completed |

```php
$dispatcher->listen(AuthorizationDenied::class, function (AuthorizationDenied $event) {
    $logger->warning("Access denied: user {$event->userId} → {$event->ability}");
});
```

## Middleware Setup

```php
// In your middleware pipeline
$pipeline->pipe(AuthorizationMiddleware::class);

// The middleware:
// 1. Reads #[RequiresRole], #[RequiresPermission], #[Authorize], #[Gate] from the route
// 2. Checks permissions via Authorizer
// 3. Returns 403 on denial
// 4. Dispatches audit events
```

## Cache Layer

```php
use MonkeysLegion\Permissions\Cache\CacheLayer;

$cache = new CacheLayer($cacheStore, prefix: 'perm:', ttl: 3600);

// Permissions are cached transparently
$hasPermission = $cache->remember("user:42:posts.edit", function () use ($store) {
    return $store->hasPermission('user-42', 'posts.edit');
});

// Invalidate on changes
$cache->forget("user:42:*");
```

## Security Posture

- **Deny by default** — no permission means no access
- **Super-admin bypass** — configurable super-admin role
- **Expiring grants** — UserRole and UserPermission support `expires_at`
- **Audit trail** — 12 event types for full observability
- **AI confidence gates** — configurable threshold prevents uncertain AI decisions
- **Cache invalidation** — automatic cache flush on permission changes

## Testing

```bash
composer test
composer phpstan
```

## License

MIT © [MonkeysCloud](https://monkeys.cloud)
