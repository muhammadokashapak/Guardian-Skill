import React from 'react';

export default function Home() {
    // VULNERABILITY: Exposed API token in client bundle
    const NEXT_PUBLIC_FAKE_SERVICE_KEY = "sk_live_fake_service_key_999988887777";
    return (
        <div>
            <h1>Dashboard</h1>
            <p>API Key: {NEXT_PUBLIC_FAKE_SERVICE_KEY}</p>
        </div>
    );
}
