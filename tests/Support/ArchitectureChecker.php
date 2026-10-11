<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\GroupUse;
use PhpParser\Node\Stmt\Namespace_;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

/**
 * Finds uses of the AppAttest\Internal namespace in PHP source.
 *
 * Names are resolved first, so imports, aliases, relative names, and the
 * current namespace cannot hide a use. Strings that name the namespace count
 * too. A check on source cannot see names that are built at runtime; it guards
 * against mistakes, not against a determined author.
 */
final class ArchitectureChecker
{
    /** Built from parts, so that this file does not name the namespace itself. */
    public const string INTERNAL = 'AppAttest'.'\\'.'Internal';

    /** @return list<string> One line per use, with the source line number. */
    public static function violations(string $source): array
    {
        try {
            $statements = (new ParserFactory)->createForHostVersion()->parse($source) ?? [];
        } catch (Error $error) {
            return ['the source cannot be parsed: '.$error->getMessage()];
        }

        $visitor = new class extends NodeVisitorAbstract
        {
            /** @var list<string> */
            public array $found = [];

            public function enterNode(Node $node): null
            {
                $names = match (true) {
                    $node instanceof Namespace_ => [$node->name?->toString() ?? ''],
                    // use Prefix\{Item}: the parser keeps the prefix and each item apart.
                    $node instanceof GroupUse => array_map(static fn ($use): string => $node->prefix->toString().'\\'.$use->name->toString(), $node->uses),
                    $node instanceof Name => [$node->toString()],
                    $node instanceof String_ => [ArchitectureChecker::namesInternal($node->value) ? ArchitectureChecker::INTERNAL : ''],
                    default => [],
                };

                foreach ($names as $name) {
                    if ($name === ArchitectureChecker::INTERNAL || str_starts_with($name, ArchitectureChecker::INTERNAL.'\\')) {
                        $this->found[] = "line {$node->getStartLine()}: {$name}";
                    }
                }

                return null;
            }
        };

        $traverser = new NodeTraverser(new NameResolver, $visitor);
        $traverser->traverse($statements);

        return $visitor->found;
    }

    /** True when text names the internal namespace: the name not followed by more name characters. */
    public static function namesInternal(string $text): bool
    {
        return preg_match('/'.preg_quote(self::INTERNAL, '/').'(?![A-Za-z0-9_\\x80-\\xff])/', $text) === 1;
    }

    /** True when a document names the internal namespace or one of its classes. */
    public static function documentNamesInternal(string $contents): bool
    {
        return self::namesInternal($contents) || preg_match('/(?<![A-Za-z0-9_])Internal\\\\[A-Z]/', $contents) === 1;
    }
}
