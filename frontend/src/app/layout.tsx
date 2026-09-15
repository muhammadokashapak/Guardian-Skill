import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Guardian AI Engineering Intelligence & Defense',
  description: 'AI Project Guardian Platform for Codebase Understanding, Security Auditing, and Safe Fix Verification',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
