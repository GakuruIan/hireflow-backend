"""fix timezone for user timestamps

Revision ID: 0d27dc91fef6
Revises: 28922c9b2292
Create Date: 2026-04-11 14:23:04.930059

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0d27dc91fef6'
down_revision: Union[str, Sequence[str], None] = '28922c9b2292'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        'user',
        'locked_until',
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        postgresql_using="locked_until AT TIME ZONE 'UTC'",
        nullable=True,
    )

    op.alter_column(
        'user',
        'last_login',
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        postgresql_using="last_login AT TIME ZONE 'UTC'",
        nullable=True,
    )

    op.alter_column(
        'user',
        'verified_at',
        existing_type=sa.DateTime(),
        type_=sa.DateTime(timezone=True),
        postgresql_using="verified_at AT TIME ZONE 'UTC'",
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        'user',
        'locked_until',
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        nullable=True,
    )

    op.alter_column(
        'user',
        'last_login',
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        nullable=True,
    )

    op.alter_column(
        'user',
        'verified_at',
        existing_type=sa.DateTime(timezone=True),
        type_=sa.DateTime(),
        nullable=True,
    )


