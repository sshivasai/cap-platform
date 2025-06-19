// File: scripts/init-mongodb.js
// MongoDB initialization script for CAP Platform

// Switch to the conversations database
db = db.getSiblingDB('cap_conversations');

// Create collections with validation
db.createCollection('conversations', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['organization_id', 'agent_id', 'session_id', 'created_at'],
            properties: {
                organization_id: { bsonType: 'string' },
                agent_id: { bsonType: 'string' },
                session_id: { bsonType: 'string' },
                user_id: { bsonType: ['string', 'null'] },
                messages: { bsonType: 'array' },
                metadata: { bsonType: 'object' },
                created_at: { bsonType: 'date' },
                updated_at: { bsonType: 'date' }
            }
        }
    }
});

db.createCollection('knowledge_base', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['organization_id', 'title', 'content', 'created_at'],
            properties: {
                organization_id: { bsonType: 'string' },
                title: { bsonType: 'string' },
                content: { bsonType: 'string' },
                file_type: { bsonType: 'string' },
                file_size: { bsonType: 'number' },
                processing_status: { 
                    enum: ['pending', 'processing', 'completed', 'failed'] 
                },
                chunks: { bsonType: 'array' },
                metadata: { bsonType: 'object' },
                created_at: { bsonType: 'date' },
                updated_at: { bsonType: 'date' }
            }
        }
    }
});

db.createCollection('user_sessions', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['session_id', 'user_id', 'created_at'],
            properties: {
                session_id: { bsonType: 'string' },
                user_id: { bsonType: 'string' },
                organization_id: { bsonType: 'string' },
                agent_id: { bsonType: 'string' },
                context: { bsonType: 'object' },
                expires_at: { bsonType: 'date' },
                created_at: { bsonType: 'date' },
                updated_at: { bsonType: 'date' }
            }
        }
    }
});

// Create indexes for performance
// Conversations indexes
db.conversations.createIndex({ 'organization_id': 1, 'created_at': -1 });
db.conversations.createIndex({ 'session_id': 1 });
db.conversations.createIndex({ 'agent_id': 1, 'created_at': -1 });
db.conversations.createIndex({ 'user_id': 1, 'created_at': -1 });

// Knowledge base indexes
db.knowledge_base.createIndex({ 'organization_id': 1, 'created_at': -1 });
db.knowledge_base.createIndex({ 'processing_status': 1 });
db.knowledge_base.createIndex({ 'title': 'text', 'content': 'text' });

// User sessions indexes
db.user_sessions.createIndex({ 'session_id': 1 }, { unique: true });
db.user_sessions.createIndex({ 'user_id': 1 });
db.user_sessions.createIndex({ 'expires_at': 1 }, { expireAfterSeconds: 0 });

// Create user with appropriate permissions
db.createUser({
    user: 'cap_user',
    pwd: 'cap_password',
    roles: [
        {
            role: 'readWrite',
            db: 'cap_conversations'
        }
    ]
});

// Switch to analytics database
db = db.getSiblingDB('cap_analytics');

// Create analytics collections
db.createCollection('conversation_analytics', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['organization_id', 'date', 'metrics'],
            properties: {
                organization_id: { bsonType: 'string' },
                agent_id: { bsonType: 'string' },
                date: { bsonType: 'date' },
                metrics: { bsonType: 'object' },
                created_at: { bsonType: 'date' }
            }
        }
    }
});

db.createCollection('usage_analytics', {
    validator: {
        $jsonSchema: {
            bsonType: 'object',
            required: ['organization_id', 'resource_type', 'usage_count', 'date'],
            properties: {
                organization_id: { bsonType: 'string' },
                resource_type: { 
                    enum: ['tokens', 'conversations', 'api_calls', 'voice_minutes'] 
                },
                usage_count: { bsonType: 'number' },
                date: { bsonType: 'date' },
                metadata: { bsonType: 'object' },
                created_at: { bsonType: 'date' }
            }
        }
    }
});

// Create analytics indexes
db.conversation_analytics.createIndex({ 'organization_id': 1, 'date': -1 });
db.conversation_analytics.createIndex({ 'agent_id': 1, 'date': -1 });
db.usage_analytics.createIndex({ 'organization_id': 1, 'resource_type': 1, 'date': -1 });

print('MongoDB initialization completed successfully');