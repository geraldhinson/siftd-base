package resourceStore

import (
	"github.com/jackc/pgx/v5"
)

// PostgresCommandHelper handles query building using pgx and named parameters.
type PostgresCommandHelper struct {
}

func (p *PostgresCommandHelper) GetResourceByIdCommand(id string) (string, pgx.NamedArgs) {
	query := `
		SELECT "Resource"
		FROM public."Resources"
		WHERE "Id" = @id;
	`
	args := pgx.NamedArgs{
		"id": id,
	}
	return query, args

	//		SELECT "Id", "OwnerId", "Version", "CreatedAt", "UpdatedAt", "Deleted", "Resource"

}

func (p *PostgresCommandHelper) GetResourcesByOwnerIdCommand(ownerId string) (string, pgx.NamedArgs) {
	query := `
		SELECT "Resource"
		FROM public."Resources"
		WHERE "OwnerId" = @ownerId
			AND "Deleted" = false;
	`
	args := pgx.NamedArgs{
		"ownerId": ownerId,
	}
	return query, args
}

func (p *PostgresCommandHelper) GetJournalChangesCommand(clock, limit int64) (string, pgx.NamedArgs) {
	query := `
		SELECT "Clock", "Resource", "CreatedAt", "PartitionName"
		FROM public."Journal"
		WHERE "Clock" >= @clock
		ORDER BY "Clock"
		LIMIT @limit;
	`
	args := pgx.NamedArgs{
		"clock": clock,
		"limit": limit,
	}
	return query, args
}

func (p *PostgresCommandHelper) GetJournalMaxClockCommand() string {
	query := `
		SELECT MAX("Clock") AS "Clock"
		FROM public."Journal";
	`
	return query
}

func (p *PostgresCommandHelper) GetInsertResourceWithJournalCommand(resource IResource, resourceJson []byte, partitionName string) (string, pgx.NamedArgs) {
	query := `
		WITH cte AS (
			INSERT INTO public."Resources"
				("Id", "OwnerId", "Version", "CreatedAt", "UpdatedAt", "Deleted", "Resource")
			VALUES
				(@id, @ownerId, @version, @createdAt, @updatedAt, @deleted, @resource)
			RETURNING "Resource"
		)
		INSERT INTO public."Journal"
			("Resource", "CreatedAt", "PartitionName")
		SELECT
			"Resource", @createdAt, @partitionName
		FROM cte
		RETURNING "Resource";
	`
	args := pgx.NamedArgs{
		"id":            resource.GetResourceBase().Id,
		"ownerId":       resource.GetResourceBase().OwnerId,
		"version":       resource.GetResourceBase().Version,
		"createdAt":     resource.GetResourceBase().CreatedAt,
		"updatedAt":     resource.GetResourceBase().UpdatedAt,
		"deleted":       resource.GetResourceBase().Deleted,
		"resource":      resourceJson,
		"partitionName": partitionName,
	}
	return query, args
}

func (p *PostgresCommandHelper) GetUpdateResourceWithJournalCommand(resource IResource, versionToUpdate uint, resourceJson []byte, partitionName string) (string, pgx.NamedArgs) {
	query := `
		WITH cte AS (
			UPDATE public."Resources"
			SET
				"Version" = @nextVersion,
				"UpdatedAt" = @updatedAt,
				"Deleted" = @deleted,
				"OwnerId" = @ownerId,
				"Resource" = @resource
			WHERE "Id" = @id
				AND "Version" = @version
				AND "OwnerId" = @ownerId
			RETURNING "Resource"
		)
		INSERT INTO public."Journal"
			("Resource", "CreatedAt", "PartitionName")
		SELECT
			"Resource", @updatedAt, @partitionName
		FROM cte
		WHERE "Resource" IS NOT NULL
		RETURNING "Resource";
	`
	args := pgx.NamedArgs{
		"nextVersion":   resource.GetResourceBase().Version,
		"updatedAt":     resource.GetResourceBase().UpdatedAt,
		"deleted":       resource.GetResourceBase().Deleted,
		"ownerId":       resource.GetResourceBase().OwnerId,
		"resource":      resourceJson,
		"id":            resource.GetResourceBase().Id,
		"version":       versionToUpdate,
		"partitionName": partitionName,
	}
	return query, args
}

func (p *PostgresCommandHelper) GetHealthCheckCommand() string {
	query := `
		SELECT 1;
	`
	return query
}
