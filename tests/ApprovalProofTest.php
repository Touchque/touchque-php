<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\ApprovalProof;
use TouchQue\Steps;

/**
 * ApprovalProof::verify against the cross-SDK golden vectors
 * (fixtures/approval-proof-vectors.json, shared with Node, Python and Go).
 */
class ApprovalProofTest extends TestCase
{
    private static function vectors(): array
    {
        return json_decode(file_get_contents(__DIR__ . '/../fixtures/approval-proof-vectors.json'), true);
    }

    public function digestCases(): array
    {
        $out = [];
        foreach (self::vectors()['digest_cases'] as $i => $c) {
            $out['digest ' . $i] = [$c['details_object'] ?? $c['details'], $c['digest']];
        }
        return $out;
    }

    public function proofCases(): array
    {
        $out = [];
        foreach (self::vectors()['cases'] as $c) {
            $out[$c['name']] = [$c['proof'], $c['options'], $c['expected']];
        }
        return $out;
    }

    /** @dataProvider digestCases */
    public function testDetailsDigest(?array $details, string $digest): void
    {
        $this->assertSame($digest, Steps::detailsDigest($details));
    }

    /** @dataProvider proofCases */
    public function testVerify(?array $proof, array $options, bool $expected): void
    {
        $this->assertSame($expected, ApprovalProof::verify($proof, $options));
    }

    public function testGarbageNeverThrows(): void
    {
        foreach ([[], ['version' => 'v2'], ['version' => 'v2', 'algorithm' => 'ECDSA-P256-SHA256', 'message' => 1, 'signature' => null, 'publicKey' => []],
                  ['version' => 'v2', 'algorithm' => 'ECDSA-P256-SHA256', 'message' => 'm', 'signature' => '%%%', 'publicKey' => '%%%']] as $proof) {
            $this->assertFalse(ApprovalProof::verify($proof, ['requestId' => 'r', 'type' => 't', 'allowUnpinnedKey' => true]));
        }
    }
}
