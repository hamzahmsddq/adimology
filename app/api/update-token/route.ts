import { NextRequest, NextResponse } from 'next/server';
import { upsertSession } from '@/lib/supabase';

// This endpoint is public (the extension has no app session), so only accept
// well-formed, unexpired JWTs to avoid overwriting the stored token with garbage.
function getJwtExpiry(token: string): number | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { token, expires_at } = body;

    if (!token) {
      return NextResponse.json(
        { success: false, error: 'Token is required' },
        { status: 400, headers: { 'Access-Control-Allow-Origin': '*' } }
      );
    }

    const jwtExp = typeof token === 'string' ? getJwtExpiry(token) : null;
    if (!jwtExp || jwtExp * 1000 <= Date.now()) {
      return NextResponse.json(
        { success: false, error: 'Token must be a valid, unexpired JWT' },
        { status: 400, headers: { 'Access-Control-Allow-Origin': '*' } }
      );
    }

    let expiresAtDate: Date | undefined;
    if (expires_at) {
      if (typeof expires_at === 'number') {
        expiresAtDate = new Date(expires_at * 1000);
      } else {
        expiresAtDate = new Date(expires_at);
      }
    }

    await upsertSession('stockbit_token', token, expiresAtDate);

    return NextResponse.json({
      success: true,
      message: 'Token updated successfully',
      expires_at: expiresAtDate,
    }, {
      headers: { 'Access-Control-Allow-Origin': '*' }
    });
  } catch (error: unknown) {
    console.error('Update Token Error:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to update token' },
      { status: 500, headers: { 'Access-Control-Allow-Origin': '*' } }
    );
  }
}
