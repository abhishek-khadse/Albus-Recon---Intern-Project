-- Initialize database with default admin user
-- This script runs when the database container starts

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create default admin user (password: admin123)
-- This should be changed immediately after first login
INSERT INTO users (username, email, hashed_password, full_name, is_superuser, role, is_active)
VALUES (
    'admin',
    'admin@albus-recon.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.s5uO9G', -- admin123
    'System Administrator',
    true,
    'admin',
    true
) ON CONFLICT (username) DO NOTHING;

-- Create sample analyst user (password: analyst123)
INSERT INTO users (username, email, hashed_password, full_name, is_superuser, role, is_active)
VALUES (
    'analyst',
    'analyst@albus-recon.local',
    '$2b$12$9X2Y4Z6a8B0c2D4e6F8g0H1j2K3l4M5n6O7p8Q9r0S1t2U3v4W5x6Y7z8A9b0C', -- analyst123
    'Security Analyst',
    false,
    'analyst',
    true
) ON CONFLICT (username) DO NOTHING;

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO albus_recon;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO albus_recon;
