package com.cloudbees.maven.plugins.autochangelog;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.factory.ArtifactFactory;
import org.apache.maven.artifact.metadata.ArtifactMetadataRetrievalException;
import org.apache.maven.artifact.metadata.ArtifactMetadataSource;
import org.apache.maven.artifact.repository.ArtifactRepository;
import org.apache.maven.artifact.resolver.ArtifactNotFoundException;
import org.apache.maven.artifact.resolver.ArtifactResolutionException;
import org.apache.maven.artifact.resolver.ArtifactResolver;
import org.apache.maven.artifact.versioning.ArtifactVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.building.ModelBuildingRequest;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.apache.maven.project.ProjectBuilder;
import org.apache.maven.project.ProjectBuildingException;
import org.apache.maven.project.ProjectBuildingRequest;
import org.apache.maven.scm.ChangeFile;
import org.apache.maven.scm.ChangeSet;
import org.apache.maven.scm.ScmException;
import org.apache.maven.scm.ScmFileSet;
import org.apache.maven.scm.ScmResult;
import org.apache.maven.scm.ScmTag;
import org.apache.maven.scm.ScmVersion;
import org.apache.maven.scm.command.changelog.ChangeLogScmResult;
import org.apache.maven.scm.command.changelog.ChangeLogSet;
import org.apache.maven.scm.manager.NoSuchScmProviderException;
import org.apache.maven.scm.manager.ScmManager;
import org.apache.maven.scm.provider.ScmProvider;
import org.apache.maven.scm.provider.ScmProviderRepository;
import org.apache.maven.scm.provider.ScmProviderRepositoryWithHost;
import org.apache.maven.scm.provider.svn.repository.SvnScmProviderRepository;
import org.apache.maven.scm.repository.ScmRepository;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.codehaus.plexus.interpolation.InterpolationException;
import org.codehaus.plexus.interpolation.Interpolator;
import org.codehaus.plexus.interpolation.PrefixAwareRecursionInterceptor;
import org.codehaus.plexus.interpolation.PrefixedPropertiesValueSource;
import org.codehaus.plexus.interpolation.RecursionInterceptor;
import org.codehaus.plexus.interpolation.StringSearchInterpolator;
import org.codehaus.plexus.util.StringUtils;
import org.codehaus.plexus.util.xml.Xpp3Dom;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.AbstractMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.regex.Pattern;

/**
 * Attaches a changelog .json as a secondary artifact to the build.
 */
@Mojo(name = "attach", aggregator = true, threadSafe = true, defaultPhase = LifecyclePhase.PACKAGE)
public class AttachMojo extends AbstractMojo {

    private static final Pattern SNAPSHOT_PATTERN = Pattern.compile("(-((\\d{8}\\.\\d{6})-(\\d+))|(SNAPSHOT))$");

    /**
     * Whether to skip to automatic changelog or not.
     */
    @Parameter(property = "autochangelog.skip", defaultValue = "false")
    private boolean skip;

    /**
     * The user name (used by svn and starteam protocol).
     */
    @Parameter(property = "username")
    private String username;

    /**
     * The user password (used by svn and starteam protocol).
     */
    @Parameter(property = "password")
    private String password;

    /**
     * The private key (used by java svn).
     */
    @Parameter(property = "privateKey")
    private String privateKey;

    /**
     * The passphrase (used by java svn).
     */
    @Parameter(property = "passphrase")
    private String passphrase;

    /**
     * The url of tags base directory (used by svn protocol).
     */
    @Parameter(property = "tagBase")
    private String tagBase;

    /**
     * Allows the user to choose which scm connection to use when connecting to the scm.
     * Can either be "connection" or "developerConnection".
     */
    @Parameter(defaultValue = "connection", required = true)
    private String connectionType;

    @Parameter(property = "project.build.outputEncoding")
    private String encoding;

    /**
     * Directory to create the changes.json file.
     */
    @Parameter(property = "project.build.directory")
    private File outputDirectory;

    @Parameter(property = "project.build.finalName")
    private String finalName;

    @Parameter(property = "project.basedir", readonly = true, required = true)
    private File basedir;

    @Parameter(property = "settings", readonly = true, required = true)
    private Settings settings;

    @Parameter(property = "project", readonly = true, required = true)
    private MavenProject project;

    @Parameter(property = "localRepository", readonly = true, required = true)
    private ArtifactRepository localRepository;

    @Parameter(property = "session", readonly = true, required = true)
    private MavenSession session;

    @Component
    private ArtifactMetadataSource artifactMetadataSource;

    @Component
    private ArtifactFactory artifactFactory;

    @Component
    private ProjectBuilder projectBuilder;

    @Component
    private ScmManager manager;

    @Component
    private MavenProjectHelper projectHelper;

    @Component
    private ArtifactResolver artifactResolver;

    private String connection = null;

    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Execution is skipped.");
            return;
        }
        getLog().debug("Looking for previous release of " + project.getGroupId() + ":" + project.getArtifactId() + ":"
                + project.getVersion());
        Artifact projectArtifact = artifactFactory
                .createProjectArtifact(project.getGroupId(), project.getArtifactId(), project.getVersion());
        ArtifactVersion projectVersion = new DefaultArtifactVersion(project.getVersion());

        ArtifactVersion latest = null;
        try {
            List<ArtifactVersion> artifactVersions = artifactMetadataSource
                    .retrieveAvailableVersions(projectArtifact, localRepository,
                            project.getRemoteArtifactRepositories());
            for (ArtifactVersion version : artifactVersions) {
                if (SNAPSHOT_PATTERN.matcher(version.toString()).find() || projectVersion.compareTo(version) <= 0) {
                    continue;
                }
                if (latest == null || latest.compareTo(version) < 0) {
                    latest = version;
                }
            }
        } catch (ArtifactMetadataRetrievalException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }
        getLog().debug("Previous release = " + latest);

        Map<GroupArtifactId, String> addedDeps = new LinkedHashMap<GroupArtifactId, String>();
        Map<GroupArtifactId, String> removedDeps = new LinkedHashMap<GroupArtifactId, String>();
        Map<GroupArtifactId, Map.Entry<String, String>> updatedDeps =
                new LinkedHashMap<GroupArtifactId, Map.Entry<String, String>>();

        for (Dependency dep : project.getDependencies()) {
            addedDeps.put(new GroupArtifactId(dep), dep.getVersion());
        }

        String startTag = null;
        String endTag = null;
        if (latest != null) {
            Artifact latestArtifact = artifactFactory
                    .createProjectArtifact(project.getGroupId(), project.getArtifactId(), latest.toString());
            try {
                artifactResolver.resolve(latestArtifact, project.getRemoteArtifactRepositories(), localRepository);
            } catch (ArtifactResolutionException e) {
                throw new MojoExecutionException(e.getMessage(), e);
            } catch (ArtifactNotFoundException e) {
                throw new MojoExecutionException(e.getMessage(), e);
            }

            ProjectBuildingRequest request = new DefaultProjectBuildingRequest();

            request.setProcessPlugins(true);
            request.setProfiles(request.getProfiles());
            request.setActiveProfileIds(session.getRequest().getActiveProfiles());
            request.setInactiveProfileIds(session.getRequest().getInactiveProfiles());
            request.setRemoteRepositories(session.getRequest().getRemoteRepositories());
            request.setSystemProperties(session.getSystemProperties());
            request.setUserProperties(session.getUserProperties());
            request.setRemoteRepositories(session.getRequest().getRemoteRepositories());
            request.setPluginArtifactRepositories(session.getRequest().getPluginArtifactRepositories());
            request.setRepositorySession(session.getRepositorySession());
            request.setLocalRepository(localRepository);
            request.setBuildStartTime(session.getRequest().getStartTime());
            request.setResolveDependencies(true);
            request.setValidationLevel(ModelBuildingRequest.VALIDATION_LEVEL_STRICT);
            MavenProject latestProject;
            try {
                latestProject = projectBuilder.build(latestArtifact.getFile(), request).getProject();
            } catch (ProjectBuildingException e) {
                throw new MojoExecutionException(e.getMessage(), e);
            }
            for (Dependency dep : latestProject.getDependencies()) {
                GroupArtifactId key = new GroupArtifactId(dep);
                if (addedDeps.containsKey(key)) {
                    String v = addedDeps.get(key);
                    addedDeps.remove(key);
                    if (!v.equals(dep.getVersion())) {
                        updatedDeps.put(key, new AbstractMap.SimpleImmutableEntry<String, String>(dep.getVersion(), v));
                    }
                } else if (updatedDeps.containsKey(key)) {
                    String v = updatedDeps.get(key).getValue();
                    if (!v.equals(dep.getVersion())) {
                        updatedDeps.remove(key);
                        addedDeps.put(key, v);
                    } else {
                        updatedDeps.put(key, new AbstractMap.SimpleImmutableEntry<String, String>(dep.getVersion(), v));
                    }
                } else {
                    removedDeps.put(key, dep.getVersion());
                }
            }

            String tagNameFormat = getTagNameFormat(latestProject);
            getLog().debug("Start Tag name format = " + tagNameFormat);
            Interpolator interpolator = new StringSearchInterpolator("@{", "}");
            List<String> possiblePrefixes = java.util.Arrays.asList("project", "pom");
            Properties values = new Properties();
            values.setProperty("artifactId", project.getArtifactId());
            values.setProperty("groupId", project.getGroupId());
            values.setProperty("version", latest.toString());
            interpolator.addValueSource(new PrefixedPropertiesValueSource(possiblePrefixes, values, true));
            RecursionInterceptor recursionInterceptor = new PrefixAwareRecursionInterceptor(possiblePrefixes);
            try {
                startTag = interpolator.interpolate(tagNameFormat, recursionInterceptor);
            } catch (InterpolationException e) {
                throw new MojoExecutionException("Could not interpolate specified tag name format: " + tagNameFormat,
                        e);
            }
        }
        if (!SNAPSHOT_PATTERN.matcher(project.getVersion()).find()) {
            String tagNameFormat = getTagNameFormat(project);
            getLog().debug("End Tag name format = " + tagNameFormat);
            Interpolator interpolator = new StringSearchInterpolator("@{", "}");
            List<String> possiblePrefixes = java.util.Arrays.asList("project", "pom");
            Properties values = new Properties();
            values.setProperty("artifactId", project.getArtifactId());
            values.setProperty("groupId", project.getGroupId());
            values.setProperty("version", project.getVersion());
            interpolator.addValueSource(new PrefixedPropertiesValueSource(possiblePrefixes, values, true));
            RecursionInterceptor recursionInterceptor = new PrefixAwareRecursionInterceptor(possiblePrefixes);
            try {
                endTag = interpolator.interpolate(tagNameFormat, recursionInterceptor);
            } catch (InterpolationException e) {
                throw new MojoExecutionException("Could not interpolate specified tag name format: " + tagNameFormat,
                        e);
            }
        }
        getLog().info("Start tag = " + startTag);
        getLog().info("End tag = " + endTag);

        ChangeLogSet changeLog = null;

        ScmRepository repository;
        try {
            repository = getScmRepository();
            ScmProvider provider = null;
            try {
                provider = manager.getProviderByRepository(repository);
            } catch (NoSuchScmProviderException e) {
                throw new MojoExecutionException("Unknown/unsupported SCM provider", e);
            }

            ScmVersion scmStartVersion;
            ScmVersion scmEndVersion;
            if (repository.getProvider().equals("svn")) {
                getLog().warn("SVN does not support the required changelog operations");
            } else {
                scmStartVersion = startTag == null ? null : new ScmTag(startTag);
                scmEndVersion = endTag == null ? null : new ScmTag(endTag);
                ChangeLogScmResult changeLogScmResult;
                try {
                    changeLogScmResult =
                            provider.changeLog(repository, new ScmFileSet(basedir), scmStartVersion, scmEndVersion);
                } catch (ScmException e) {
                    throw new MojoExecutionException("Could not fetch changelog", e);
                }
                checkResult(changeLogScmResult);

                changeLog = changeLogScmResult.getChangeLog();
            }
        } catch (ScmException e) {
            getLog().error("Could not get SCM repository", e);
        }

        if (StringUtils.isEmpty(encoding)) {
            getLog().warn("Output file encoding has not been set, using platform encoding " + System
                    .getProperty("file.encoding") + ", i.e. build is platform dependent!");
            encoding = System.getProperty("file.encoding");
        }

        if (!outputDirectory.isDirectory() && !outputDirectory.mkdirs()) {
            throw new MojoExecutionException("Could not create directory " + outputDirectory);
        }

        File outputFile = new File(outputDirectory, finalName + "-changes.json");

        JsonFactory factory = new JsonFactory();
        try {
            JsonGenerator generator = factory.createJsonGenerator(outputFile, JsonEncoding.UTF8);
            generator.setPrettyPrinter(new DefaultPrettyPrinter());
            try {
                generator.writeStartObject();
                generator.writeFieldName("dependencies");
                writeDependenciesDelta(addedDeps, removedDeps, updatedDeps, generator);
                if (changeLog != null) {
                    generator.writeFieldName("scm");
                    writeChangeLog(generator, changeLog);
                }
                generator.writeEndObject();
            } finally {
                generator.close();
            }
        } catch (IOException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }
        projectHelper.attachArtifact(project, "json", "changes", outputFile);
    }

    private void writeDependenciesDelta(Map<GroupArtifactId, String> addedDeps,
                                        Map<GroupArtifactId, String> removedDeps,
                                        Map<GroupArtifactId, Map.Entry<String, String>> updatedDeps,
                                        JsonGenerator generator) throws IOException {
        generator.writeStartObject();
        if (!addedDeps.isEmpty()) {
            generator.writeArrayFieldStart("added");
            for (Map.Entry<GroupArtifactId, String> e : addedDeps.entrySet()) {
                generator.writeStartObject();
                generator.writeStringField("groupId", e.getKey().getGroupId());
                generator.writeStringField("artifactId", e.getKey().getArtifactId());
                generator.writeStringField("version", e.getValue());
                generator.writeEndObject();
            }
            generator.writeEndArray();
        }
        if (!removedDeps.isEmpty()) {
            generator.writeArrayFieldStart("removed");
            for (Map.Entry<GroupArtifactId, String> e : removedDeps.entrySet()) {
                generator.writeStartObject();
                generator.writeStringField("groupId", e.getKey().getGroupId());
                generator.writeStringField("artifactId", e.getKey().getArtifactId());
                generator.writeStringField("version", e.getValue());
                generator.writeEndObject();
            }
            generator.writeEndArray();
        }
        if (!updatedDeps.isEmpty()) {
            generator.writeArrayFieldStart("updated");
            for (Map.Entry<GroupArtifactId, Map.Entry<String, String>> e : updatedDeps.entrySet()) {
                generator.writeStartObject();
                generator.writeStringField("groupId", e.getKey().getGroupId());
                generator.writeStringField("artifactId", e.getKey().getArtifactId());
                generator.writeStringField("version", e.getValue().getValue());
                generator.writeStringField("originalVersion", e.getValue().getKey());
                generator.writeEndObject();
            }
            generator.writeEndArray();
        }
        generator.writeEndObject();
    }

    private String getTagNameFormat(MavenProject project) {
        Plugin releasePlugin = null;
        for (Plugin plugin : project.getBuild().getPlugins()) {
            if ("org.apache.maven.plugins".equals(plugin.getGroupId()) && "maven-release-plugin"
                    .equals(plugin.getArtifactId())) {
                releasePlugin = plugin;
                break;
            }
        }
        String tagNameFormat = "@{project.artifactId}-@{project.version}";
        if (releasePlugin != null) {
            Xpp3Dom dom = (Xpp3Dom) releasePlugin.getConfiguration();
            Xpp3Dom tagNameFormatDom = dom.getChild("tagNameFormat");
            if (tagNameFormatDom != null) {
                tagNameFormat = tagNameFormatDom.getValue();
            }
        }
        return tagNameFormat;
    }

    private void writeChangeLog(JsonGenerator generator, ChangeLogSet changeLog) throws IOException {
        generator.writeStartArray();
        try {
            for (ChangeSet changeSet : changeLog.getChangeSets()) {
                writeChangeSet(generator, changeSet);
            }
        } finally {
            generator.writeEndArray();
        }
    }

    private void writeChangeSet(JsonGenerator generator, ChangeSet changeSet) throws IOException {
        generator.writeStartObject();
        try {
            if (StringUtils.isNotEmpty(changeSet.getAuthor())) {
                generator.writeStringField("author", changeSet.getAuthor());
            }
            if (StringUtils.isNotEmpty(changeSet.getComment())) {
                generator.writeStringField("comment", changeSet.getComment());
            }
            if (changeSet.getDate() != null) {
                SimpleDateFormat iso8601format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                iso8601format.setTimeZone(TimeZone.getTimeZone("UTC"));
                generator.writeStringField("date", iso8601format.format(changeSet.getDate()));
            }
            if (changeSet.getParentRevision() != null) {
                generator.writeStringField("parentRevision", changeSet.getParentRevision());
            }
            if (!changeSet.getMergedRevisions().isEmpty()) {
                generator.writeArrayFieldStart("mergedRevisions");
                try {
                    for (String revision : changeSet.getMergedRevisions()) {
                        generator.writeString(revision);
                    }
                } finally {
                    generator.writeEndArray();
                }
            }
            if (!changeSet.getFiles().isEmpty()) {
                generator.writeArrayFieldStart("files");
                try {
                    for (ChangeFile file : changeSet.getFiles()) {
                        writeChangeFile(generator, file);
                    }
                } finally {
                    generator.writeEndArray();
                }
            }
        } finally {
            generator.writeEndObject();
        }
    }

    private void writeChangeFile(JsonGenerator generator, ChangeFile file) throws IOException {
        generator.writeStartObject();
        try {
            if (file.getAction() != null) {
                generator.writeStringField("action", file.getAction().toString());
            }
            if (file.getName() != null) {
                generator.writeStringField("name", file.getName());
            }
            if (file.getRevision() != null) {
                generator.writeStringField("revision", file.getRevision());
            }
            if (file.getOriginalName() != null) {
                generator.writeStringField("originalName", file.getOriginalName());
            }
            if (file.getOriginalRevision() != null) {
                generator.writeStringField("originalRevision", file.getOriginalRevision());
            }
        } finally {
            generator.writeEndObject();
        }
    }

    public ScmRepository getScmRepository()
            throws ScmException {
        ScmRepository repository;

        try {
            repository = manager.makeScmRepository(getConnection());

            ScmProviderRepository providerRepo = repository.getProviderRepository();

            if (!StringUtils.isEmpty(username)) {
                providerRepo.setUser(username);
            }

            if (!StringUtils.isEmpty(password)) {
                providerRepo.setPassword(password);
            }

            if (repository.getProviderRepository() instanceof ScmProviderRepositoryWithHost) {
                ScmProviderRepositoryWithHost repo = (ScmProviderRepositoryWithHost) repository.getProviderRepository();

                loadInfosFromSettings(repo);

                if (!StringUtils.isEmpty(username)) {
                    repo.setUser(username);
                }

                if (!StringUtils.isEmpty(password)) {
                    repo.setPassword(password);
                }

                if (!StringUtils.isEmpty(privateKey)) {
                    repo.setPrivateKey(privateKey);
                }

                if (!StringUtils.isEmpty(passphrase)) {
                    repo.setPassphrase(passphrase);
                }
            }

            if (!StringUtils.isEmpty(tagBase) && repository.getProvider().equals("svn")) {
                SvnScmProviderRepository svnRepo = (SvnScmProviderRepository) repository.getProviderRepository();

                svnRepo.setTagBase(tagBase);
            }
        } catch (Exception e) {
            throw new ScmException("Can't load the scm provider.", e);
        }

        return repository;
    }

    /**
     * Load username password from settings if user has not set them in JVM properties
     *
     * @param repo
     */
    private void loadInfosFromSettings(ScmProviderRepositoryWithHost repo) {
        if (username == null || password == null) {
            String host = repo.getHost();

            int port = repo.getPort();

            if (port > 0) {
                host += ":" + port;
            }

            Server server = this.settings.getServer(host);

            if (server != null) {
                if (username == null) {
                    username = this.settings.getServer(host).getUsername();
                }

                if (password == null) {
                    password = this.settings.getServer(host).getPassword();
                }

                if (privateKey == null) {
                    privateKey = this.settings.getServer(host).getPrivateKey();
                }

                if (passphrase == null) {
                    passphrase = this.settings.getServer(host).getPassphrase();
                }
            }
        }
    }

    public void checkResult(ScmResult result)
            throws MojoExecutionException {
        if (!result.isSuccess()) {
            getLog().error("Provider message:");

            getLog().error(result.getProviderMessage() == null ? "" : result.getProviderMessage());

            getLog().error("Command output:");

            getLog().error(result.getCommandOutput() == null ? "" : result.getCommandOutput());

            throw new MojoExecutionException("Command failed.");
        }
    }

    /**
     * used to retrieve the SCM connection string
     *
     * @return the url string used to connect to the SCM
     * @throws MojoExecutionException when there is insufficient information to retrieve the SCM connection string
     */
    protected String getConnection()
            throws MojoExecutionException {
        if (this.connection != null) {
            return connection;
        }

        if (project.getScm() == null) {
            throw new MojoExecutionException("SCM Connection is not set.");
        }

        String scmConnection = project.getScm().getConnection();
        if (StringUtils.isNotEmpty(scmConnection) && "connection".equals(connectionType.toLowerCase())) {
            connection = scmConnection;
        }

        String scmDeveloper = project.getScm().getDeveloperConnection();
        if (StringUtils.isNotEmpty(scmDeveloper) && "developerconnection".equals(connectionType.toLowerCase())) {
            connection = scmDeveloper;
        }

        if (StringUtils.isEmpty(connection)) {
            throw new MojoExecutionException("SCM Connection is not set.");
        }

        return connection;
    }

    /**
     * Determines the relative path from trunk to tag, and adds this relative path
     * to the url.
     *
     * @param trunkPath - The trunk url
     * @param tagPath   - The tag base
     * @param urlPath   - scm.url or scm.connection
     * @return The url path for the tag.
     */
    private String translateUrlPath(String trunkPath, String tagPath, String urlPath) {
        trunkPath = trunkPath.trim();
        tagPath = tagPath.trim();
        //Strip the slash at the end if one is present
        if (trunkPath.endsWith("/")) {
            trunkPath = trunkPath.substring(0, trunkPath.length() - 1);
        }
        if (tagPath.endsWith("/")) {
            tagPath = tagPath.substring(0, tagPath.length() - 1);
        }
        char[] tagPathChars = trunkPath.toCharArray();
        char[] trunkPathChars = tagPath.toCharArray();
        // Find the common path between trunk and tags
        int i = 0;
        while ((i < tagPathChars.length) && (i < trunkPathChars.length) && tagPathChars[i] == trunkPathChars[i]) {
            ++i;
        }
        // If there is nothing common between trunk and tags, or the relative
        // path does not exist in the url, then just return the tag.
        if (i == 0 || urlPath.indexOf(trunkPath.substring(i)) < 0) {
            return tagPath;
        } else {
            return StringUtils.replace(urlPath, trunkPath.substring(i), tagPath.substring(i));
        }
    }

    private static class GroupArtifactId {
        private final String groupId;
        private final String artifactId;

        public GroupArtifactId(Dependency dependency) {
            this.groupId = dependency.getGroupId();
            this.artifactId = dependency.getArtifactId();
        }

        public String getArtifactId() {
            return artifactId;
        }

        public String getGroupId() {
            return groupId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            GroupArtifactId that = (GroupArtifactId) o;

            if (artifactId != null ? !artifactId.equals(that.artifactId) : that.artifactId != null) {
                return false;
            }
            if (groupId != null ? !groupId.equals(that.groupId) : that.groupId != null) {
                return false;
            }

            return true;
        }

        @Override
        public int hashCode() {
            int result = groupId != null ? groupId.hashCode() : 0;
            result = 31 * result + (artifactId != null ? artifactId.hashCode() : 0);
            return result;
        }

        @Override
        public String toString() {
            return getGroupId() + ":" + getArtifactId();
        }
    }

}
