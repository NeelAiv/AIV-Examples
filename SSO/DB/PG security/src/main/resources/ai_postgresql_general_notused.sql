CREATE SCHEMA IF NOT EXISTS "XXXXX" AUTHORIZATION postgres;//@
CREATE TABLE "XXXXX".ai_user
(
  id serial NOT NULL,
  firstname character varying(255),
  lastname character varying(255),
  username character varying(255),
  status character varying(255),
  password character varying(255),
  email character varying(255),
  homefolder character varying(255),
  backupuserid character varying(255),
  manageruserid character varying(255),
  dashboardoption character varying(1) default '0',
  alertsOption character varying(1) default '0',
  reportOption character varying(1) default '0',
  mergeReportOption character varying(1) default '0',
  adhocOption character varying(1) default '0',
  resourceOption character varying(1) default '0',
  quickRunOption character varying(1) default '0',
  mappingOption character varying(1) default '0',
  messageOption character varying(1) default '0',
  datasetOption character varying(1) default '0',
  parameterOption character varying(1) default '0',
  annotationOption character varying(1) default '0',
  notificationOption character varying(1) default '0',
  requestOption character varying(1) default '0',
  adminOption character varying(1) default '0',
  scheduleOption character varying(1) default '0',
  usertype character varying(255),
  default_dashboard character varying(255),
landing_page character varying(255),
locale character varying(255),
timezone character varying(255),
theme character varying(255),
notification character varying(1) default '0',
department character varying(255),
showname character varying(1) default '1',
showimage character varying(1) default '1',
  CONSTRAINT ai_user_pkey PRIMARY KEY (id),
  CONSTRAINT ai_user_username_key UNIQUE (username)
);//@

CREATE TABLE "XXXXX".ai_role
(
  id serial NOT NULL,
  name character varying(255),
  description character varying(255),
  email character varying(255),
  dashboardoption character varying(1) default '0',
  alertsOption character varying(1) default '0',
  reportOption character varying(1) default '0',
  mergeReportOption character varying(1) default '0',
  adhocOption character varying(1) default '0',
  resourceOption character varying(1) default '0',
  quickRunOption character varying(1) default '0',
  mappingOption character varying(1) default '0',
  messageOption character varying(1) default '0',
  datasetOption character varying(1) default '0',
  parameterOption character varying(1) default '0',
  annotationOption character varying(1) default '0',
  notificationOption character varying(1) default '0',
  requestOption character varying(1) default '0',
  adminOption character varying(1) default '0',
  scheduleOption character varying(1) default '0',
  department character varying(255),
  CONSTRAINT ai_role_pkey PRIMARY KEY (id),
  CONSTRAINT ai_role_name_key UNIQUE (name)
);//@

CREATE TABLE "XXXXX".ai_user_role
(
  id serial NOT NULL,
  userName character varying(255),
  roleName character varying(255),
  CONSTRAINT ai_user_role_pkey PRIMARY KEY (id),
  CONSTRAINT ai_user_role_ukey UNIQUE (userName,roleName)
);//@


commit;//@