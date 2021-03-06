"""empty message

Revision ID: 05f96bae63df
Revises: 35030803cb96
Create Date: 2020-10-10 22:09:56.020964

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '05f96bae63df'
down_revision = '35030803cb96'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('global_settings', sa.Column('events_page_refresh', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('global_settings', 'events_page_refresh')
    # ### end Alembic commands ###
