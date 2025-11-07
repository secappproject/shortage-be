DROP TABLE IF EXISTS detected_parts;
DROP TABLE IF EXISTS actual_parts;
DROP TABLE IF EXISTS comparison;
DROP TABLE IF EXISTS project_tracking;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS bom;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS vendors;
DROP TYPE IF EXISTS user_role;
DROP TYPE IF EXISTS test_status_enum;

CREATE TYPE user_role AS ENUM ('Admin', 'PIC', 'Production Planning', 'External/Vendor');

CREATE TYPE test_status_enum AS ENUM ('Waiting', 'Tested', 'Already Compared with BOM');

CREATE TABLE vendors (
    id SERIAL PRIMARY KEY,
    company_name VARCHAR(100) UNIQUE NOT NULL, 
    vendor_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role user_role NOT NULL,
    company_name VARCHAR(100), 
    vendor_type VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE bom (
    id SERIAL PRIMARY KEY,
    bom_code VARCHAR(100) NOT NULL,
    version_tag VARCHAR(100) NOT NULL DEFAULT 'default',
    part_reference VARCHAR(255),
    material VARCHAR(100) NOT NULL,
    material_description TEXT,
    qty INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(bom_code, version_tag, material) 
);


CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    wbs_number VARCHAR(100) UNIQUE NOT NULL,
    project_name VARCHAR(255) NOT NULL,
    vendor_name VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE project_tracking (
    id SERIAL PRIMARY KEY,
    project_id INT REFERENCES projects(id) ON DELETE SET NULL, 
    switchboard_name VARCHAR(255) NOT NULL,
    compartment_number VARCHAR(100) NOT NULL,
    mech_assembly_by VARCHAR(100),
    wiring_type VARCHAR(100),
    wiring_by VARCHAR(100),
    status_test test_status_enum NOT NULL DEFAULT 'Waiting',
    tested_by VARCHAR(100),
    date_tested TIMESTAMPTZ,
    detection_settings JSONB, 
    detection_results JSONB,  
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE actual_parts (
    id SERIAL PRIMARY KEY,
    tracking_id INT NOT NULL REFERENCES project_tracking(id) ON DELETE CASCADE,
    material VARCHAR(100) NOT NULL,
    actual_qty INT NOT NULL DEFAULT 1,
    views JSONB,
    UNIQUE(tracking_id, material)
);

CREATE TABLE comparison (
    id SERIAL PRIMARY KEY,
    bom_code VARCHAR(100) NOT NULL,
    version_tag VARCHAR(100) NOT NULL DEFAULT 'default',
    tracking_id INT NOT NULL REFERENCES project_tracking(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    
    shortage_items JSONB DEFAULT '[]'::jsonb,
    excess_items JSONB DEFAULT '[]'::jsonb,
    unlisted_items JSONB DEFAULT '[]'::jsonb,
    
    UNIQUE(bom_code, version_tag, tracking_id)
);

CREATE TABLE bom_active_versions (
    bom_code VARCHAR(100) PRIMARY KEY,
    active_version_tag VARCHAR(100) NOT NULL
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

CREATE TRIGGER update_vendors_updated_at
BEFORE UPDATE ON vendors
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_bom_updated_at
BEFORE UPDATE ON bom
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_projects_updated_at
BEFORE UPDATE ON projects
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_project_tracking_updated_at
BEFORE UPDATE ON project_tracking
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


INSERT INTO vendors (company_name, vendor_type) VALUES
('ABACUS', 'Panel'),
('UMEDA', 'Panel'),
('GAA', 'Panel'),
('Triakarya', 'Busbar'),
('Globalindo', 'Busbar'),
('Presisi', 'Busbar');

INSERT INTO users (username, password, role) VALUES
('admin', 'adminpass', 'Admin'),
('pic_user', 'picpass', 'PIC'),
('pp_user', 'pppass', 'Production Planning');

INSERT INTO users (username, password, role, company_name, vendor_type) VALUES
('vendor_abacus', 'abacuspass', 'External/Vendor', 'ABACUS', 'Panel'),
('vendor_umeda', 'umedapass', 'External/Vendor', 'UMEDA', 'Panel');

DO $$
DECLARE
    bom_codes TEXT[] := ARRAY['BC-01', 'BC-02', 'BC-03', 'BC-04', 'BC-05'];
    materials TEXT[] := ARRAY[
        'Auxiliary',
        'Base Plate',
        'Box',
        'Connection Power Supply',
        'Door Handle Drawer',
        'Drawer Stopper',
        'Front Plate',
        'Handle Drawer',
        'Index Mechanism',
        'Locking Mechanism',
        'Mounting Component',
        'Push Button Index Mechanism',
        'Roda Drawer',
        'Support Outgoing',
        'Top Plate'
    ];
    versions TEXT[] := ARRAY['default', 'v1.1'];
    i INT;
    j INT;
    k INT;
BEGIN
    FOR i IN 1..array_length(bom_codes, 1) LOOP
        FOR k IN 1..array_length(versions, 1) LOOP
            FOR j IN 1..array_length(materials, 1) LOOP
                INSERT INTO bom (bom_code, version_tag, part_reference, material, material_description, qty)
                VALUES (
                    bom_codes[i],
                    versions[k],
                    FORMAT('REF-%s%02s', i, j),
                    materials[j],
                    FORMAT('%s for %s assembly', materials[j], bom_codes[i]),
                    ((j + i + k) % 10) + 1
                )
                ON CONFLICT (bom_code, version_tag, material) DO NOTHING;
            END LOOP;
        END LOOP;
    END LOOP;
END $$;


INSERT INTO projects (project_name, wbs_number, vendor_name) VALUES
('NQC OEKEN', 'C2010-4048786-200', 'GAA'),
('Proyek Gedung B', 'WBS-002', 'UMEDA')
RETURNING id;

INSERT INTO project_tracking (
    project_id, 
    switchboard_name, 
    compartment_number, 
    mech_assembly_by, 
    wiring_type, 
    wiring_by, 
    status_test, 
    tested_by, 
    date_tested
)
VALUES
(
    1, 'B2 EN 465', 'FA6-07', 'Bowo', 'LV F2-BB', 'Nopi', 
    'Waiting', NULL, NULL
),
(
    1, 'B2 EN 465', 'FA6-08', 'Bowo', 'LV F2-BB', 'Nopi', 
    'Waiting', NULL, NULL
);

INSERT INTO bom_active_versions (bom_code, active_version_tag)
SELECT DISTINCT bom_code, 'default'
FROM bom
ON CONFLICT (bom_code) DO NOTHING;