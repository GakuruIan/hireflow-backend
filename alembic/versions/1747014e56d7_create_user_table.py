"""create user table

Revision ID: 1747014e56d7
Revises: 
Create Date: 2026-04-05 17:41:52.720042

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers
revision: str = '1747014e56d7'
down_revision: Union[str, Sequence[str], None] = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'user',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('fullname', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password', sa.String(), nullable=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False),
        
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.DateTime(), nullable=True),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index('ix_user_email', 'user', ['email'], unique=True)
    op.create_index('ix_user_fullname', 'user', ['fullname'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_user_fullname', table_name='user')
    op.drop_index('ix_user_email', table_name='user')
    op.drop_table('user')