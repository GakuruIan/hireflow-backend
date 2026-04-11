"""drop access token from session table

Revision ID: 98469b1e66f9
Revises: 0d27dc91fef6
Create Date: 2026-04-11 15:15:19.382735

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '98469b1e66f9'
down_revision: Union[str, Sequence[str], None] = '0d27dc91fef6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("session", "access_token")


def downgrade() -> None:
    op.add_column("session", sa.Column("access_token", sa.String(), nullable=False))
