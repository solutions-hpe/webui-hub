"""Initial schema migration."""

from alembic import op
import sqlalchemy as sa


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=True)

    op.create_table(
        'workspaces',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('aruba_workspace_id', sa.String(length=255), nullable=True),
        sa.Column('ownership', sa.String(length=32), nullable=False),
        sa.Column('aruba_config', sa.Text(), nullable=True),
        sa.Column('notification_config', sa.Text(), nullable=True),
        sa.Column('central_poll_enabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'sites',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('api_key', sa.String(length=36), nullable=True),
        sa.Column('workspace_id', sa.Uuid(), nullable=True),
        sa.Column('label', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('telemetry_json', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_sites_api_key', 'sites', ['api_key'], unique=True)
    op.create_index('ix_sites_hostname', 'sites', ['hostname'], unique=True)
    op.create_index('ix_sites_status', 'sites', ['status'], unique=False)

    op.create_table(
        'commands',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('site_id', sa.Uuid(), nullable=True),
        sa.Column('workspace_id', sa.Uuid(), nullable=True),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('delivered_at', sa.DateTime(), nullable=True),
        sa.Column('executed_at', sa.DateTime(), nullable=True),
        sa.Column('result_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_commands_site_id', 'commands', ['site_id'], unique=False)
    op.create_index('ix_commands_status', 'commands', ['status'], unique=False)
    op.create_index('ix_commands_workspace_id', 'commands', ['workspace_id'], unique=False)

    op.create_table(
        'checks',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('workspace_id', sa.Uuid(), nullable=False),
        sa.Column('check_name', sa.String(length=255), nullable=False),
        sa.Column('check_type', sa.String(length=32), nullable=False),
        sa.Column('timeout_minutes', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('last_confirmed_at', sa.DateTime(), nullable=True),
        sa.Column('last_reported_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_checks_workspace_id', 'checks', ['workspace_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_checks_workspace_id', table_name='checks')
    op.drop_table('checks')

    op.drop_index('ix_commands_workspace_id', table_name='commands')
    op.drop_index('ix_commands_status', table_name='commands')
    op.drop_index('ix_commands_site_id', table_name='commands')
    op.drop_table('commands')

    op.drop_index('ix_sites_status', table_name='sites')
    op.drop_index('ix_sites_hostname', table_name='sites')
    op.drop_index('ix_sites_api_key', table_name='sites')
    op.drop_table('sites')

    op.drop_table('workspaces')

    op.drop_index('ix_users_username', table_name='users')
    op.drop_table('users')
