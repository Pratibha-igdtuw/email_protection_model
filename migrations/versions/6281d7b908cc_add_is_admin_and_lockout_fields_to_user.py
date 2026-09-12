"""add is_admin and lockout fields to user

Revision ID: 6281d7b908cc
Revises: 3d34d0b03245
Create Date: 2026-09-12 14:30:01.510481

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6281d7b908cc'
down_revision = '3d34d0b03245'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_admin', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('locked_until', sa.DateTime(), nullable=True))

    # Drop the server defaults now that existing rows are backfilled —
    # new rows will get their defaults from the User model instead.
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('is_admin', server_default=None)
        batch_op.alter_column('failed_login_attempts', server_default=None)


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_attempts')
        batch_op.drop_column('is_admin')