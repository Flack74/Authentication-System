#!/bin/bash

echo "🔍 Authentication System Inspector"
echo "================================="

# Function to decode JWT
decode_jwt() {
    echo "JWT Payload:"
    echo "$1" | cut -d. -f2 | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "Invalid JWT"
}

# Test login and show tokens
echo "1. Testing login with existing user..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"finaltest@example.com","password":"password123"}')

if echo "$LOGIN_RESPONSE" | grep -q "access_token"; then
    echo "✅ Login successful!"
    
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
    REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.refresh_token')
    
    echo ""
    echo "🎫 ACCESS TOKEN:"
    echo "$ACCESS_TOKEN"
    echo ""
    decode_jwt "$ACCESS_TOKEN"
    
    echo ""
    echo "🔄 REFRESH TOKEN:"
    echo "$REFRESH_TOKEN"
    echo ""
    decode_jwt "$REFRESH_TOKEN"
    
    echo ""
    echo "2. Testing protected endpoint..."
    PROFILE_RESPONSE=$(curl -s -X GET http://localhost:8080/api/profile \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    echo "Profile Response:"
    echo "$PROFILE_RESPONSE" | jq .
    
else
    echo "❌ Login failed: $LOGIN_RESPONSE"
fi

echo ""
echo "3. Database Users:"
docker-compose exec postgres psql -U authuser -d authdb -c "SELECT email, email_verified, created_at FROM users ORDER BY created_at DESC LIMIT 3;" 2>/dev/null

echo ""
echo "4. Redis Token Count:"
echo "Refresh tokens: $(docker-compose exec redis redis-cli KEYS 'refresh_token:*' 2>/dev/null | wc -l)"
echo "Blacklisted tokens: $(docker-compose exec redis redis-cli KEYS 'blacklist:*' 2>/dev/null | wc -l)"
