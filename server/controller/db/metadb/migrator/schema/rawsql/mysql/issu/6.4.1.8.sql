DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

CREATE PROCEDURE AddColumnIfNotExists(
    IN dbName VARCHAR(255),
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    -- check if column exists
    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE table_schema = dbName
    AND table_name = tableName
    AND column_name = colName;

    -- add column if column does not exist 
    IF column_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnIfNotExists('zerotrace', 'process', 'devicetype', 'INTEGER');
CALL AddColumnIfNotExists('zerotrace', 'process', 'deviceid', 'INTEGER');
CALL AddColumnIfNotExists('zerotrace', 'process', 'pod_node_id', 'INTEGER');
CALL AddColumnIfNotExists('zerotrace', 'process', 'vm_id', 'INTEGER');

DROP PROCEDURE AddColumnIfNotExists;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.4.1.8';
-- modify end
