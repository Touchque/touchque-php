<?php

namespace TouchQue\Tests;

use PHPUnit\Framework\TestCase;
use TouchQue\Exceptions\TouchQueConfigException;
use TouchQue\Http\HttpClient;
use TouchQue\Resources\Login;
use TouchQue\Resources\Risk;

class RiskTest extends TestCase
{
    private const NORMAL_ASK = ['prompt' => true, 'reasons' => [], 'assurance' => 'normal', 'silentMode' => 'enforce'];

    public function testAnythingButAJsonObjectAsks(): void
    {
        foreach ([null, 'false', false, 0, [], [false], ['prompt' => 0], ['prompt' => null], ['prompt' => 'false'], ['prompt' => []]] as $raw) {
            $this->assertSame(self::NORMAL_ASK, Risk::parseCheck($raw), json_encode($raw));
        }
    }

    public function testReasonEntriesWithoutAStringCodeAreDroppedAndAMissingTextIsEmpty(): void
    {
        $res = Risk::parseCheck(['prompt' => true, 'reasons' => [
            null, ['code' => 1], ['code' => 'new_browser'], 'x', ['code' => 'risk_signal', 'text' => 'Risk signal: tor_exit_node'],
        ]]);
        $this->assertSame([['code' => 'new_browser', 'text' => ''], ['code' => 'risk_signal', 'text' => 'Risk signal: tor_exit_node']], $res['reasons']);
        // An object instead of a list is malformed too.
        $this->assertSame([], Risk::parseCheck(['prompt' => true, 'reasons' => ['code' => 'new_browser', 'text' => 'x']])['reasons']);
    }

    public function testUnknownAssuranceIsNormalAndOnlyShadowIsShadow(): void
    {
        $res = Risk::parseCheck(['prompt' => false, 'assurance' => 'ultra', 'silentMode' => 'SHADOW']);
        $this->assertFalse($res['prompt']);
        $this->assertSame('normal', $res['assurance']);
        $this->assertSame('enforce', $res['silentMode']);
        $this->assertSame('shadow', Risk::parseCheck(['prompt' => true, 'silentMode' => 'shadow'])['silentMode']);
    }

    public function testCheckSendsOnlyTheGivenCamelCaseOptions(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(2))->method('post')->withConsecutive(
            ['/risk/check', ['externalUsername' => 'jane@acme.com']],
            ['/risk/check', ['externalUsername' => 'jane@acme.com', 'type' => 'SEND_MONEY', 'clientIp' => '203.0.113.7', 'userAgent' => 'UA', 'browserProof' => 'eyJ2IjoxfQ', 'maxAgeSeconds' => 0]]
        )->willReturn(['prompt' => false, 'reasons' => [['code' => 'known_browser', 'text' => 'Known']], 'assurance' => 'high', 'silentMode' => 'enforce']);
        $risk = new Risk($http);
        $risk->check(['externalUsername' => 'jane@acme.com', 'type' => null, 'clientIp' => '', 'browserProof' => null]);
        $res = $risk->check([
            'externalUsername' => 'jane@acme.com', 'type' => 'SEND_MONEY', 'clientIp' => '203.0.113.7', 'userAgent' => 'UA',
            'browserProof' => 'eyJ2IjoxfQ', 'maxAgeSeconds' => 0,
        ]);
        $this->assertSame(['prompt' => false, 'reasons' => [['code' => 'known_browser', 'text' => 'Known']], 'assurance' => 'high', 'silentMode' => 'enforce'], $res);
    }

    public function testBadOptionsAreRefusedBeforeAnyCall(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->never())->method('post');
        $http->expects($this->never())->method('get');
        $risk = new Risk($http);
        $cases = [
            fn () => $risk->check([]),
            fn () => $risk->check(['externalUsername' => '']),
            fn () => $risk->check(['externalUsername' => 'jane@acme.com', 'browser_proof' => 'x']),
            fn () => $risk->check(['externalUsername' => 'jane@acme.com', 'maxAgeSeconds' => -1]),
            fn () => $risk->check(['externalUsername' => 'jane@acme.com', 'maxAgeSeconds' => '3600']),
            fn () => $risk->check(['externalUsername' => 'jane@acme.com', 'browserProof' => ['v' => 1]]),
            fn () => $risk->browsers([]),
            fn () => $risk->browsers(['external_username' => 'jane@acme.com']),
            fn () => $risk->forgetBrowsers(['thumbprint' => 'abc']),
        ];
        foreach ($cases as $i => $call) {
            try {
                $call();
                $this->fail("case $i: expected TouchQueConfigException");
            } catch (TouchQueConfigException $e) {
                $this->assertStringStartsWith('risk->', $e->getMessage(), "case $i");
            }
        }
    }

    public function testBrowsersAndForgetBrowsers(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(2))->method('get')->with('/risk/browsers', ['externalUsername' => 'jane@acme.com'])
            ->willReturnOnConsecutiveCalls(['browsers' => [['thumbprint' => 't1']]], ['browsers' => 'nope']);
        $http->expects($this->exactly(2))->method('post')->withConsecutive(
            ['/risk/browsers/forget', ['externalUsername' => 'jane@acme.com', 'thumbprint' => 't1']],
            ['/risk/browsers/forget', ['externalUsername' => 'jane@acme.com']]
        )->willReturnOnConsecutiveCalls(['forgotten' => 1], ['forgotten' => 3]);
        $risk = new Risk($http);
        $this->assertSame(['browsers' => [['thumbprint' => 't1']]], $risk->browsers(['externalUsername' => 'jane@acme.com']));
        $this->assertSame(['browsers' => []], $risk->browsers(['externalUsername' => 'jane@acme.com']));
        $this->assertSame(['forgotten' => 1], $risk->forgetBrowsers(['externalUsername' => 'jane@acme.com', 'thumbprint' => 't1']));
        $this->assertSame(['forgotten' => 3], $risk->forgetBrowsers(['externalUsername' => 'jane@acme.com', 'thumbprint' => null]));
    }

    public function testLoginRequestSendsTheProofOnlyWhenGiven(): void
    {
        $http = $this->createMock(HttpClient::class);
        $http->expects($this->exactly(2))->method('post')->withConsecutive(
            ['/login/request', ['externalUsername' => 'jane@acme.com', 'type' => 'LOGIN', 'browserProof' => 'eyJ2IjoxfQ']],
            ['/login/request', ['externalUsername' => 'jane@acme.com', 'type' => 'LOGIN']]
        )->willReturn(['requestId' => 'req_1']);
        $login = new Login($http);
        $login->request('jane@acme.com', 'LOGIN', null, null, null, false, false, null, 'eyJ2IjoxfQ');
        $login->request('jane@acme.com', 'LOGIN', null, null, null, false, false, null, '');
    }
}
