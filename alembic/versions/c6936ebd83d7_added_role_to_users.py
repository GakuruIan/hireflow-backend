"""added role to users

Revision ID: c6936ebd83d7
Revises: 98469b1e66f9
Create Date: 2026-04-12 12:57:31.752834

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c6936ebd83d7'
down_revision: Union[str, Sequence[str], None] = '98469b1e66f9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("role", sa.String(), nullable=True)  # start nullable for safety
    )
    # ### end Alembic commands ###


def downgrade() -> None:
     op.drop_column("user", "role")
    # ### end Alembic commands ###
