<?php

namespace Selective\XmlDSig;

use DOMNode;
use DOMXPath;
use UnexpectedValueException;

/**
 * A Xml Reader.
 */
final class XmlReader
{
    /**
     * Query the first dome node item.
     *
     * @param DOMXPath $xpath The xpath
     * @param string $expression The xpath expression
     * @param DOMNode $contextNode The context node
     *
     * @throws UnexpectedValueException
     *
     * @return DOMNode The first item
     */
    public function queryDomNode(DOMXPath $xpath, string $expression, DOMNode $contextNode): DOMNode
    {
        $nodeList = $xpath->query($expression, $contextNode);

        if (!$nodeList) {
            throw new UnexpectedValueException('Signature value not found');
        }

        $item = $nodeList->item(0);
        if ($item === null) {
            throw new UnexpectedValueException('Signature value not found');
        }

        return $item;
    }
}
