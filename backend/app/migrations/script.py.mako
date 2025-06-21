# File: backend/app/migrations/script.py.mako
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

This migration was generated for the CAP Platform.
Please review the migration before applying to production.

Migration Type: ${"Initial" if not down_revision else "Update"}
Tables Affected: ${", ".join([op.table_name for op in upgrade_ops.ops if hasattr(op, 'table_name')]) if upgrade_ops.ops else "Multiple/Various"}
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: Union[str, None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}


def upgrade() -> None:
    """
    Upgrade database schema.
    
    This function contains the forward migration logic.
    All changes here should be reversible in the downgrade() function.
    """
    # Migration safety check
    print(f"Applying migration: ${message}")
    
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """
    Downgrade database schema.
    
    This function contains the reverse migration logic.
    Should undo all changes made in the upgrade() function.
    """
    # Migration safety check
    print(f"Reversing migration: ${message}")
    
    ${downgrades if downgrades else "pass"}