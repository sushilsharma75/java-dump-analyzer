"""Versioned, value-free metadata from optional DDL files. Never executable SQL."""

from pydantic import BaseModel, Field


class SchemaColumn(BaseModel):
    name: str
    data_type: str
    nullable: bool = True
    primary_key: bool = False
    unique: bool = False


class SchemaIndex(BaseModel):
    name: str
    table: str
    columns: list[str] = Field(default_factory=list)
    unique: bool = False
    primary: bool = False
    plain_btree: bool = False


class SchemaTable(BaseModel):
    name: str
    columns: list[SchemaColumn] = Field(default_factory=list)
    referenced_tables: list[str] = Field(default_factory=list)


class VariableInfo(BaseModel):
    name: str
    data_type: str
    kind: str  # parameter or local
    declaration_line: int
    occurrences: int = 0  # lexical references; not a data-flow proof
    assignment_lines: list[int] = Field(default_factory=list)


class TempTableInfo(BaseModel):
    name: str
    creation_line: int
    columns: list[str] = Field(default_factory=list)
    indexes: list[str] = Field(default_factory=list)
    read_lines: list[int] = Field(default_factory=list)
    write_lines: list[int] = Field(default_factory=list)
    drop_lines: list[int] = Field(default_factory=list)


class RoutineStatement(BaseModel):
    line: int
    kind: str
    normalized_sql: str
    tables: list[str] = Field(default_factory=list)
    parsed: bool = False


class RoutineInfo(BaseModel):
    source_file: int = 1
    name: str
    kind: str
    language: str
    line: int
    parameters: list[VariableInfo] = Field(default_factory=list)
    variables: list[VariableInfo] = Field(default_factory=list)
    temporary_tables: list[TempTableInfo] = Field(default_factory=list)
    statements: list[RoutineStatement] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    loop_lines: list[int] = Field(default_factory=list)
    branch_lines: list[int] = Field(default_factory=list)
    dynamic_sql_lines: list[int] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class SchemaCatalog(BaseModel):
    format_version: int = 1
    engine: str
    source_count: int = 0
    tables: list[SchemaTable] = Field(default_factory=list)
    indexes: list[SchemaIndex] = Field(default_factory=list)
    views: list[str] = Field(default_factory=list)
    routines: list[RoutineInfo] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Static analysis only: no SQL is executed and no runtime values or row "
            "counts are inferred.",
            "Dynamic SQL, procedural control flow, variable scope and execution plans "
            "require manual review.",
            "DDL must correspond to the snapshot database; unqualified names are not "
            "mapped across databases.",
        ]
    )
