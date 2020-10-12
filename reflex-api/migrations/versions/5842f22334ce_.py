"""empty message

Revision ID: 5842f22334ce
Revises: a94c67faa9ea
Create Date: 2020-10-05 20:25:49.081602

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '5842f22334ce'
down_revision = 'a94c67faa9ea'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('case_task', sa.Column('finish_date', sa.DateTime(), nullable=True))
    op.add_column('case_task', sa.Column('start_date', sa.DateTime(), nullable=True))
    op.drop_column('task_note', 'finish_date')
    op.drop_column('task_note', 'start_date')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('task_note', sa.Column('start_date', mysql.DATETIME(), nullable=True))
    op.add_column('task_note', sa.Column('finish_date', mysql.DATETIME(), nullable=True))
    op.drop_column('case_task', 'start_date')
    op.drop_column('case_task', 'finish_date')
    # ### end Alembic commands ###
