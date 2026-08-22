/**
 * SentinelMail AI - Forensic Sample Email Datasets
 * Pre-configured realistic raw email headers and bodies for 1-click hackathon demonstrations.
 */

const SAMPLE_EMAILS = {
    sbi_phishing: {
        id: "sbi_phishing",
        title: "SBI Bank KYC Suspension (Phishing & Domain Spoof)",
        threatLevel: "CRITICAL",
        category: "Credential Harvesting / Banking Phishing",
        description: "Spoofed banking alert claiming urgent KYC update required within 24 hours. Originates from a Russian bulletproof hosting server with failed DMARC.",
        raw: `Delivered-To: victim.user@corporate-enterprise.in
Received: by 2002:a05:6512:4b4:0:0:0:0 with SMTP id v4csp12345678lfl;
        Fri, 21 Aug 2026 14:22:15 +0530 (IST)
X-Received: by 2002:a17:907:23cd:0:0:0:0 with SMTP id gl13-20020a17090723cd00b00a3d4f8287cesmr2847291ejc.34.2026.08.21.01.52.14;
        Fri, 21 Aug 2026 01:52:14 -0700 (PDT)
Authentication-Results: mx.corporate-enterprise.in;
        dkim=fail header.i=@sbi-online-security.in header.s=default;
        spf=fail (mx.corporate-enterprise.in: domain of alert@sbi-online-security.in does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=alert@sbi-online-security.in;
        dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=sbi.co.in
Received-SPF: fail (corporate-enterprise.in: domain of alert@sbi-online-security.in does not designate 185.220.101.5 as permitted sender)
Received: from mail-relay-nl.anonym-routing.net (mail-relay-nl.anonym-routing.net. [185.220.101.5])
        by mx.corporate-enterprise.in with ESMTPS id q87si3891024ejf.192.2026.08.21.01.52.13
        for <victim.user@corporate-enterprise.in>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Aug 2026 01:52:13 -0700 (PDT)
Received: from vps-node-88.bulletproof-host.ru (vps-node-88.bulletproof-host.ru [94.156.65.112])
        by mail-relay-nl.anonym-routing.net (Postfix) with ESMTP id 4X9kL30m8Zz3wK
        for <victim.user@corporate-enterprise.in>; Fri, 21 Aug 2026 10:51:48 +0200 (CEST)
Received: from [194.26.29.134] (unknown [194.26.29.134])
        by vps-node-88.bulletproof-host.ru (Postfix) with ESMTPA id 3F0B91840A;
        Fri, 21 Aug 2026 11:51:22 +0300 (MSK)
From: "State Bank of India Online Security" <support@sbi.co.in>
Reply-To: "Verification Desk" <recovery-auth-sbi@sbi-online-security.in>
Return-Path: <alert@sbi-online-security.in>
To: <victim.user@corporate-enterprise.in>
Subject: URGENT: Mandatory KYC Verification Pending - Account Block Warning!
Date: Fri, 21 Aug 2026 14:21:10 +0530
Message-ID: <20260821142110.3F0B91840A@vps-node-88.bulletproof-host.ru>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit
X-Mailer: PHPMailer 6.4.0 (https://github.com/PHPMailer/PHPMailer)
X-Priority: 1 (Highest)

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
<div style="background-color: #003366; padding: 15px; text-align: center; color: white;">
    <h2>STATE BANK OF INDIA - SECURE BANKING PORTAL</h2>
</div>
<div style="padding: 20px;">
    <p>Dear Valued SBI Customer,</p>
    <p><strong style="color: red;">IMMEDIATE ACTION REQUIRED:</strong> Your NetBanking profile and debit cards will be <strong>permanently suspended within 24 hours</strong> due to incomplete RBI mandatory KYC documentation.</p>
    <p>To avoid transaction termination and a penalty fee of Rs. 2,500, please verify your Aadhaar and NetBanking login credentials immediately on our secure server.</p>
    <div style="text-align: center; margin: 30px 0;">
        <a href="http://login-sbi-bank.update-kyc.ru/portal/auth.php?ref=49201" style="background-color: #28a745; color: white; padding: 14px 28px; text-decoration: none; font-weight: bold; border-radius: 4px; font-size: 16px;">UPDATE KYC NOW</a>
    </div>
    <p>Failure to complete this verification by midnight will result in freezing of your savings account.</p>
    <p>Sincerely,<br>SBI Customer Protection Department<br>State Bank Bhavan, Nariman Point, Mumbai</p>
</div>
</body>
</html>`
    },

    ceo_bec_fraud: {
        id: "ceo_bec_fraud",
        title: "CEO Urgent Wire Transfer (Business Email Compromise)",
        threatLevel: "CRITICAL",
        category: "Business Email Compromise (BEC) / Wire Fraud",
        description: "Executive impersonation targeting Chief Financial Officer to execute an off-book confidential acquisition payment via offshore escrow.",
        raw: `Delivered-To: cfo.finance@techcorp-global.com
Received: by 2002:a05:6402:22cf:0:0:0:0 with SMTP id bt15csp4910283edb;
        Thu, 20 Aug 2026 16:45:10 -0700 (PDT)
X-Received: by 2002:a0c:8a87:0:0:0:0 with SMTP id y7-20020a0c8a87000000b00624519961f0mr1938562clc.8.2026.08.20.16.45.10;
        Thu, 20 Aug 2026 16:45:10 -0700 (PDT)
Authentication-Results: mx.techcorp-global.com;
        dkim=pass header.i=@gmail.com header.s=20230601;
        spf=pass (mx.techcorp-global.com: domain of exec.sundar.pichai.desk@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=exec.sundar.pichai.desk@gmail.com;
        dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=techcorp-global.com
Received-SPF: pass (techcorp-global.com: domain of exec.sundar.pichai.desk@gmail.com designates 209.85.220.41 as permitted sender)
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.techcorp-global.com with SMTPS id x12sor4819280cla.5.2026.08.20.16.45.09
        for <cfo.finance@techcorp-global.com>;
        Thu, 20 Aug 2026 16:45:09 -0700 (PDT)
Received: from [103.145.74.88] (vpn-sg-node1.expressvpn-exit.net [103.145.74.88])
        by smtp.gmail.com with ESMTPSA id b13-20020a05620a168d00b00799ec8b02bdsm5192831qki.112.2026.08.20.16.45.07
        for <cfo.finance@techcorp-global.com>;
        Thu, 20 Aug 2026 16:45:08 -0700 (PDT)
From: "Sundar Pichai (CEO)" <sundar.pichai@techcorp-global.com>
Reply-To: "Sundar Pichai (Private Desk)" <exec.sundar.pichai.desk@gmail.com>
Return-Path: <exec.sundar.pichai.desk@gmail.com>
To: <cfo.finance@techcorp-global.com>
Subject: CONFIDENTIAL & URGENT: Project Titan Escrow Wire Transfer
Date: Thu, 20 Aug 2026 16:44:50 -0700
Message-ID: <CACG8-w0G9yP1M=kG+g1gK=2VdZp2s_v94Wj_01xQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Priority: 1 (Highest)

Hi Robert,

Are you at your desk right now?

I am currently in an NDA-restricted board meeting regarding our confidential acquisition of Project Titan in Asia. 

I need you to urgently process an initial escrow wire payment of $385,000 to our legal counsel's acquisition escrow account before the foreign exchange cutoff today (5:00 PM EST).

Due to SEC confidentiality rules, do not discuss this through standard office channels or call my assistant. Reply directly to this email with the wire confirmation form so I can sign off on it immediately.

Please confirm you have received this and I will send over the international beneficiary routing details right away.

Best regards,

Sundar Pichai
Chief Executive Officer
TechCorp Global Inc.`
    },

    m365_credential_harvest: {
        id: "m365_credential_harvest",
        title: "Microsoft 365 Password Expiry Trap (Punycode & Typosquat)",
        threatLevel: "HIGH",
        category: "Credential Harvesting / Typosquatting",
        description: "Attackers created a lookalike domain 'm1crosoft-security-verify.com' using display spoofing and hidden redirection tokens.",
        raw: `Delivered-To: employee.dev@innovatech.org
Received: by 2002:a17:906:8ec4:0:0:0:0 with SMTP id b4csp2841029ejt;
        Wed, 19 Aug 2026 09:12:44 +0000 (UTC)
Authentication-Results: mx.innovatech.org;
        dkim=neutral (message not signed);
        spf=softfail (mx.innovatech.org: transitioning domain of admin@m1crosoft-security-verify.com does not designate 45.142.214.201 as permitted sender) smtp.mailfrom=admin@m1crosoft-security-verify.com;
        dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=microsoft.com
Received-SPF: softfail (innovatech.org: transitioning domain of admin@m1crosoft-security-verify.com)
Received: from mail.m1crosoft-security-verify.com (mail.m1crosoft-security-verify.com [45.142.214.201])
        by mx.innovatech.org with ESMTP id u19si5819382ejp.41.2026.08.19.09.12.42
        for <employee.dev@innovatech.org>;
        Wed, 19 Aug 2026 09:12:43 +0000 (UTC)
Received: from [102.89.41.155] (host-102-89-41-155.cloud-lagos.ng [102.89.41.155])
        by mail.m1crosoft-security-verify.com (Postfix) with ESMTPA id 829A02B18E;
        Wed, 19 Aug 2026 10:12:10 +0100 (WAT)
From: "Microsoft 365 Security Team" <account-security-noreply@microsoft.com>
Reply-To: "Office 365 Admin Helpdesk" <support@m1crosoft-security-verify.com>
Return-Path: <admin@m1crosoft-security-verify.com>
To: <employee.dev@innovatech.org>
Subject: Alert: Your Microsoft 365 Password Expires in 2 Hours (Keep Current Password)
Date: Wed, 19 Aug 2026 09:11:58 +0000
Message-ID: <0100018a14b5c7e1-38914c90-000000@email.amazonses.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px;">
<div style="max-width: 600px; margin: auto; background: white; border: 1px solid #ddd; border-radius: 6px; overflow: hidden;">
    <div style="background-color: #0078d4; color: white; padding: 20px;">
        <h2 style="margin: 0; font-size: 20px;">Microsoft Office 365 Security Center</h2>
    </div>
    <div style="padding: 25px; color: #242424;">
        <p>Hello User,</p>
        <p>Your organizational password for <strong>employee.dev@innovatech.org</strong> is scheduled to expire today at <strong>11:30 AM UTC</strong>.</p>
        <p>To retain your existing password and prevent disruption to Outlook, OneDrive, and Microsoft Teams, please re-authenticate below:</p>
        <div style="margin: 30px 0; text-align: center;">
            <a href="https://auth.m1crosoft-security-verify.com/login.php?user=employee.dev@innovatech.org&token=98af0c9b" style="background: #0078d4; color: white; padding: 12px 24px; text-decoration: none; font-weight: 600; border-radius: 4px;">KEEP MY CURRENT PASSWORD</a>
        </div>
        <p style="font-size: 12px; color: #777;">If no action is taken within 120 minutes, your mailbox will be locked by IT administration.</p>
    </div>
</div>
</body>
</html>`
    },

    legitimate_google_mail: {
        id: "legitimate_google_mail",
        title: "Legitimate Google Cloud Billing Invoice (Clean / Verified)",
        threatLevel: "CLEAN",
        category: "Legitimate Enterprise Communication",
        description: "Fully authenticated corporate billing invoice from Google LLC with valid cryptographic DKIM signature and strict DMARC pass.",
        raw: `Delivered-To: sysadmin@company-cloud.io
Received: by 2002:a05:6512:1086:0:0:0:0 with SMTP id b6csp1029482lfa;
        Tue, 18 Aug 2026 18:30:25 -0700 (PDT)
X-Received: by 2002:a17:902:c28e:0:0:0:0 with SMTP id x14-20020a170902c28e00b0019e078cb845mr10294819ccd.45.2026.08.18.18.30.25;
        Tue, 18 Aug 2026 18:30:25 -0700 (PDT)
Authentication-Results: mx.company-cloud.io;
        dkim=pass header.i=@google.com header.s=20230601;
        spf=pass (mx.company-cloud.io: domain of 3eJ-YQw0KDA0-abfghij.google.com designates 209.85.220.69 as permitted sender) smtp.mailfrom=3eJ-YQw0KDA0-abfghij.google.com;
        dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received-SPF: pass (company-cloud.io: domain of 3eJ-YQw0KDA0-abfghij.google.com designates 209.85.220.69 as permitted sender)
Received: from mail-sor-f69.google.com (mail-sor-f69.google.com. [209.85.220.69])
        by mx.company-cloud.io with SMTPS id t23sor5910281ccd.1.2026.08.18.18.30.24
        for <sysadmin@company-cloud.io>;
        Tue, 18 Aug 2026 18:30:24 -0700 (PDT)
Received: from google.com ([172.217.16.14])
        by mail-sor-f69.google.com with ESMTPSA id q8-20020a170902c28e00b0019e078cb845sm10294819ccd.45;
        Tue, 18 Aug 2026 18:30:22 -0700 (PDT)
From: "Google Cloud Platform" <cloud-noreply@google.com>
Reply-To: "Google Cloud Support" <google-cloud-support@google.com>
Return-Path: <3eJ-YQw0KDA0-abfghij.google.com>
To: <sysadmin@company-cloud.io>
Subject: Your Google Cloud Invoice is Available for Account ID: 0192-3849-5821
Date: Tue, 18 Aug 2026 18:30:20 -0700
Message-ID: <0100018a14b5c7e1-38914c90-000000@email.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hello Google Cloud Customer,

Your monthly invoice for Google Cloud services (Billing Account: 0192-3849-5821) is now ready to view in the Google Cloud Console.

Invoice Number: IN-2026-08-98421
Billing Period: Jul 1, 2026 - Jul 31, 2026
Total Amount: $42.50 USD
Payment Status: Automatically charged to primary Visa ending in 4012.

To view your itemized usage breakdown, download PDF tax invoices, or modify billing settings, visit:
https://console.cloud.google.com/billing

Thank you for choosing Google Cloud.

Google Cloud Billing Team
1600 Amphitheatre Parkway, Mountain View, CA 94043, USA`
    }
};

// Known GeoIP Mock Intelligence Database for simulation & fast offline fallback
const GEO_IP_DATABASE = {
    "194.26.29.134": {
        ip: "194.26.29.134",
        city: "Moscow",
        region: "Moscow City",
        country: "Russian Federation",
        countryCode: "RU",
        lat: 55.7558,
        lng: 37.6173,
        isp: "Selectel Infrastructure Networks",
        asn: "AS49505 (SELECTEL-AS)",
        organization: "Private Bulletproof Hosting",
        proxy: true,
        vpn: false,
        tor: false,
        hosting: true,
        threatScore: 88,
        riskFactors: ["Bulletproof Hosting Subnet", "High Fraud Historical Ratio", "Unregistered Mailer Agent"]
    },
    "94.156.65.112": {
        ip: "94.156.65.112",
        city: "Saint Petersburg",
        region: "Northwestern",
        country: "Russian Federation",
        countryCode: "RU",
        lat: 59.9343,
        lng: 30.3351,
        isp: "Miranda Media LLC",
        asn: "AS200000 (MIRANDA-AS)",
        organization: "St. Petersburg Relay Node",
        proxy: true,
        vpn: false,
        tor: false,
        hosting: true,
        threatScore: 75,
        riskFactors: ["Relay Manipulation Identified", "Known Spamhaus XBL Blacklist"]
    },
    "185.220.101.5": {
        ip: "185.220.101.5",
        city: "Amsterdam",
        region: "North Holland",
        country: "Netherlands",
        countryCode: "NL",
        lat: 52.3676,
        lng: 4.9041,
        isp: "Zwiebelfreunde e.V. Privacy Network",
        asn: "AS200651 (TOR-EXIT-NET)",
        organization: "Tor Exit Relay Cluster",
        proxy: true,
        vpn: false,
        tor: true,
        hosting: true,
        threatScore: 92,
        riskFactors: ["Verified TOR Exit Node", "Anonymized Origin", "DMARC Alignment Failure"]
    },
    "103.145.74.88": {
        ip: "103.145.74.88",
        city: "Singapore",
        region: "Central Singapore",
        country: "Singapore",
        countryCode: "SG",
        lat: 1.3521,
        lng: 103.8198,
        isp: "Datacamp Limited",
        asn: "AS60068 (DATACAMP-AS)",
        organization: "Commercial VPN Exit Gateway",
        proxy: true,
        vpn: true,
        tor: false,
        hosting: true,
        threatScore: 68,
        riskFactors: ["Commercial VPN IP", "Origin Mismatch with Claimed CEO Profile", "Off-hours Submission"]
    },
    "209.85.220.41": {
        ip: "209.85.220.41",
        city: "Mountain View",
        region: "California",
        country: "United States",
        countryCode: "US",
        lat: 37.422,
        lng: -122.0841,
        isp: "Google LLC",
        asn: "AS15169 (GOOGLE)",
        organization: "Google Workspace Mail Routing",
        proxy: false,
        vpn: false,
        tor: false,
        hosting: true,
        threatScore: 5,
        riskFactors: []
    },
    "45.142.214.201": {
        ip: "45.142.214.201",
        city: "Frankfurt",
        region: "Hesse",
        country: "Germany",
        countryCode: "DE",
        lat: 50.1109,
        lng: 8.6821,
        isp: "HostRoyale Technologies",
        asn: "AS44592 (HOSTROYALE)",
        organization: "Disposable Cloud VPS",
        proxy: true,
        vpn: false,
        tor: false,
        hosting: true,
        threatScore: 78,
        riskFactors: ["Recently Provisioned IP Subnet", "SPF SoftFail", "Mismatched Sender ID"]
    },
    "102.89.41.155": {
        ip: "102.89.41.155",
        city: "Lagos",
        region: "Lagos State",
        country: "Nigeria",
        countryCode: "NG",
        lat: 6.5244,
        lng: 3.3792,
        isp: "MTN Nigeria Communications",
        asn: "AS29465 (MTN-NIGERIA)",
        organization: "Mobile Telecom Uplink",
        proxy: false,
        vpn: false,
        tor: false,
        hosting: false,
        threatScore: 72,
        riskFactors: ["Direct Dialup/Residential Mail Origin", "Geo Disparity with US Tech Identity"]
    },
    "209.85.220.69": {
        ip: "209.85.220.69",
        city: "Mountain View",
        region: "California",
        country: "United States",
        countryCode: "US",
        lat: 37.422,
        lng: -122.0841,
        isp: "Google LLC",
        asn: "AS15169 (GOOGLE)",
        organization: "Google Production Mail Cluster",
        proxy: false,
        vpn: false,
        tor: false,
        hosting: true,
        threatScore: 0,
        riskFactors: []
    },
    "172.217.16.14": {
        ip: "172.217.16.14",
        city: "Mountain View",
        region: "California",
        country: "United States",
        countryCode: "US",
        lat: 37.422,
        lng: -122.0841,
        isp: "Google LLC",
        asn: "AS15169 (GOOGLE)",
        organization: "Google Cloud Internal Network",
        proxy: false,
        vpn: false,
        tor: false,
        hosting: true,
        threatScore: 0,
        riskFactors: []
    }
};

// Target Organization (Simulated Victim Endpoint for Map hops)
const VICTIM_ORGANIZATION_ENDPOINT = {
    city: "New Delhi",
    region: "Delhi",
    country: "India",
    countryCode: "IN",
    lat: 28.6139,
    lng: 77.2090,
    isp: "National Informatics & Enterprise Gateway",
    asn: "AS55824 (NIC-INDIA)"
};
