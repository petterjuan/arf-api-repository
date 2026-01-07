"""Initial schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2024-01-08 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create enum types
    incident_severity = postgresql.ENUM('low', 'medium', 'high', 'critical', name='incidentseverity')
    incident_status = postgresql.ENUM('open', 'investigating', 'resolved', 'closed', name='incidentstatus')
    incident_type = postgresql.ENUM('system', 'security', 'performance', 'data_loss', 'llm', 'agent', 'other', name='incidenttype')
    
    incident_severity.create(op.get_bind())
    incident_status.create(op.get_bind())
    incident_type.create(op.get_bind())
    
    # Create incidents table
    op.create_table('incidents',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', incident_severity, nullable=False),
        sa.Column('status', incident_status, nullable=False),
        sa.Column('incident_type', incident_type, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('source_system', sa.String(length=200), nullable=True),
        sa.Column('component', sa.String(length=200), nullable=True),
        sa.Column('agent_id', sa.String(length=100), nullable=True),
        sa.Column('llm_provider', sa.String(length=100), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('affected_users', sa.Integer(), nullable=True),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('resolution', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index('ix_incidents_created_at', 'incidents', ['created_at'])
    op.create_index('ix_incidents_severity', 'incidents', ['severity'])
    op.create_index('ix_incidents_status', 'incidents', ['status'])
    op.create_index('ix_incidents_incident_type', 'incidents', ['incident_type'])


def downgrade():
    op.drop_index('ix_incidents_incident_type', table_name='incidents')
    op.drop_index('ix_incidents_status', table_name='incidents')
    op.drop_index('ix_incidents_severity', table_name='incidents')
    op.drop_index('ix_incidents_created_at', table_name='incidents')
    op.drop_table('incidents')
    
    incident_severity = postgresql.ENUM(name='incidentseverity')
    incident_status = postgresql.ENUM(name='incidentstatus')
    incident_type = postgresql.ENUM(name='incidenttype')
    
    incident_severity.drop(op.get_bind())
    incident_status.drop(op.get_bind())
    incident_type.drop(op.get_bind())
