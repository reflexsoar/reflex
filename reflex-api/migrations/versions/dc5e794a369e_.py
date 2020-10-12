"""empty message

Revision ID: dc5e794a369e
Revises: 39af70860e32
Create Date: 2020-10-04 14:24:29.883657

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dc5e794a369e'
down_revision = '39af70860e32'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('task_note',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('uuid', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('modified_at', sa.DateTime(), nullable=True),
    sa.Column('note', sa.Text(), nullable=False),
    sa.Column('task_uuid', sa.String(length=255), nullable=True),
    sa.Column('created_by_uuid', sa.String(length=255), nullable=True),
    sa.Column('updated_by_uuid', sa.String(length=255), nullable=True),
    sa.Column('organization_uuid', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['created_by_uuid'], ['user.uuid'], ),
    sa.ForeignKeyConstraint(['organization_uuid'], ['organization.uuid'], ),
    sa.ForeignKeyConstraint(['task_uuid'], ['case_task.uuid'], ),
    sa.ForeignKeyConstraint(['updated_by_uuid'], ['user.uuid'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('uuid')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('task_note')
    # ### end Alembic commands ###